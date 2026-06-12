import asyncio
import argparse
import csv
import os
import time
import psutil as _psutil
import slixmpp
from slixmpp.xmlstream import ET
from crypto.pqc_wrapper import PQCProvider
from crypto import xmpp_env
from metrics.realtime import RealtimeStats

NS = "urn:uma:tfm:pqc:0"

OUT_CSV = "artifacts/csv/sender_metrics.csv"

_PROC = _psutil.Process()

# Algoritmos disponibles (family, alg_name)
_ALL_ALGS = [
    ("ML-DSA",  "ML-DSA-65"),
    ("SPHINCS", "SPHINCS+-SHA2-128s-simple"),
]

# Mapa para filtrar por familia desde --algorithms
_ALG_FAMILIES = {
    "ML-DSA":   [("ML-DSA",  "ML-DSA-65")],
    "SPHINCS":  [("SPHINCS", "SPHINCS+-SHA2-128s-simple")],
    "all":      _ALL_ALGS,
}


class EmisorBench(slixmpp.ClientXMPP):
    def __init__(self, jid, password, recipient, startup_timeout_s=20,
                 algs=None, iterations=100):
        super().__init__(jid, password)

        self.use_tls = False
        self.use_ssl = False
        self.force_starttls = False
        self["feature_mechanisms"].unencrypted_plain = True

        self.boundjid.resource = "bench"

        self.recipient = recipient
        self.startup_timeout_s = startup_timeout_s
        self.session_ready = False
        self.exit_code = 0
        self.pqc = PQCProvider()
        self.algs = algs if algs is not None else _ALL_ALGS
        self.iterations = max(1, iterations)

        self.pending = {}  # msg_id -> (send_time_perf, future)
        self.net_baseline_rtt_ms = float("nan")

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("receipt_received", self.on_receipt)
        self.add_event_handler("failed_auth", self.on_failed_auth)
        self.add_event_handler("connection_failed", self.on_connection_failed)
        self.add_event_handler("disconnected", self.on_disconnected)

        # CSV
        self.csv_f = open(OUT_CSV, "w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.csv_f, fieldnames=[
            "ts_unix",
            "alg_family",
            "alg_name",
            "seq",
            "msg_id",
            "body_bytes",
            "stanza_bytes",
            "pk_b64_bytes",
            "sig_b64_bytes",
            "sig_keygen_time_ms",
            "sign_time_ms",
            "serialize_time_ms",
            "rtt_ms",
            "net_baseline_rtt_ms",
            "receipt_ok",
            "mem_rss_kb",
            "mem_delta_kb",
            "cpu_user_ms",
            "cpu_sys_ms",
        ])
        self.writer.writeheader()
        self.stats = RealtimeStats(window=50)

    async def start(self, _):
        self.session_ready = True
        self.send_presence()
        await self.get_roster()
        await asyncio.sleep(0.2)

        print("EmisorBench listo. Guardando en:", OUT_CSV)
        self.net_baseline_rtt_ms = await self._measure_baseline_rtt(n=5)
        print(f"Baseline RTT (sin PQC): {self.net_baseline_rtt_ms:.2f} ms")
        await self.run_benchmark()
        self.exit_code = 0
        self.disconnect()
        # Dar tiempo a slixmpp para cerrar el stream y luego forzar parada
        await asyncio.sleep(0.5)
        asyncio.get_event_loop().stop()

    def on_failed_auth(self, _):
        if not self.session_ready:
            print("ERROR: autenticación XMPP fallida (usuario/contraseña).")
            self.exit_code = 2
            self.disconnect()

    def on_connection_failed(self, _):
        if not self.session_ready:
            print("WARN: conexión XMPP fallida; reintentando hasta timeout de arranque.")

    def on_disconnected(self, _):
        if not self.session_ready and self.exit_code == 0:
            self.exit_code = 2

    def _startup_watchdog(self):
        if not self.session_ready:
            print(f"ERROR: timeout de arranque ({self.startup_timeout_s}s) esperando session_start.")
            self.exit_code = 2
            self.disconnect()

    def on_receipt(self, msg):
        # msg['receipt'] contiene el id del mensaje recibido
        msg_id = msg["receipt"]
        if msg_id in self.pending:
            t_send, fut = self.pending.pop(msg_id)
            rtt_ms = (time.perf_counter() - t_send) * 1000.0
            if not fut.done():
                fut.set_result(rtt_ms)

    async def _measure_baseline_rtt(self, n: int = 5) -> float:
        """Mide el RTT de mensajes XMPP sin PQC (referencia de latencia de red)."""
        rtts = []
        for _ in range(n):
            msg = self.make_message(mto=self.recipient, mbody="__baseline__", mtype="chat")
            msg_id = msg["id"] = self.new_id()
            msg["request_receipt"] = True
            fut = asyncio.get_event_loop().create_future()
            t_send = time.perf_counter()
            self.pending[msg_id] = (t_send, fut)
            msg.send()
            try:
                rtt = await asyncio.wait_for(fut, timeout=5.0)
                rtts.append(rtt)
            except asyncio.TimeoutError:
                self.pending.pop(msg_id, None)
            await asyncio.sleep(0.05)
        return sum(rtts) / len(rtts) if rtts else float("nan")

    async def run_benchmark(self):
        seq_global = 0

        for family, alg_name in self.algs:
            n = self.iterations
            print(f"\n== Benchmark {family}: {alg_name} ({n} mensajes) ==")
            for i in range(1, n + 1):
                seq_global += 1
                body = f"[{family} #{i}] Mensaje benchmark UMA"
                body_bytes = len(body.encode("utf-8"))

                # Keygen + firma separados para medir ambos tiempos
                _t_cpu0 = _PROC.cpu_times()
                _mem0_kb = _PROC.memory_info().rss >> 10
                kp = self.pqc.generate_signature_keypair(alg_name)
                sign_res = self.pqc.sign_with_secret_key(
                    alg_name,
                    body.encode("utf-8"),
                    kp.secret_key_b64,
                    kp.public_key_b64,
                )
                _mem1_kb = _PROC.memory_info().rss >> 10
                _t_cpu1 = _PROC.cpu_times()
                cpu_user_ms = (_t_cpu1.user - _t_cpu0.user) * 1000.0
                cpu_sys_ms  = (_t_cpu1.system - _t_cpu0.system) * 1000.0
                mem_rss_kb   = _mem1_kb
                mem_delta_kb = _mem1_kb - _mem0_kb

                # Serializar stanza con campos PQC (medir tiempo)
                _t0_ser = time.perf_counter()
                msg = self.make_message(mto=self.recipient, mbody=body, mtype="chat")
                msg_id = msg["id"] = self.new_id()
                msg["request_receipt"] = True

                pqc_tag = ET.Element(f"{{{NS}}}pqc_auth")
                pqc_tag.set("alg", alg_name)

                sig_el = ET.SubElement(pqc_tag, f"{{{NS}}}sig")
                sig_el.text = sign_res.sig_b64

                pk_el = ET.SubElement(pqc_tag, f"{{{NS}}}pk")
                pk_el.text = kp.public_key_b64

                msg.xml.append(pqc_tag)

                stanza_bytes = len(ET.tostring(msg.xml, encoding="utf-8"))
                serialize_time_ms = (time.perf_counter() - _t0_ser) * 1000.0

                pk_b64_bytes = len(kp.public_key_b64.encode("ascii"))
                sig_b64_bytes = len(sign_res.sig_b64.encode("ascii"))

                # Enviar y esperar receipt con timeout
                fut = asyncio.get_event_loop().create_future()
                t_send = time.perf_counter()
                self.pending[msg_id] = (t_send, fut)

                msg.send()

                rtt_ms = float("nan")
                receipt_ok = 0
                try:
                    rtt_ms = await asyncio.wait_for(fut, timeout=10.0)
                    receipt_ok = 1
                except asyncio.TimeoutError:
                    # no receipt; lo dejamos como NaN y seguimos
                    if msg_id in self.pending:
                        self.pending.pop(msg_id, None)

                row = {
                    "ts_unix": time.time(),
                    "alg_family": family,
                    "alg_name": alg_name,
                    "seq": i,
                    "msg_id": msg_id,
                    "body_bytes": body_bytes,
                    "stanza_bytes": stanza_bytes,
                    "pk_b64_bytes": pk_b64_bytes,
                    "sig_b64_bytes": sig_b64_bytes,
                    "sig_keygen_time_ms": kp.keygen_time_ms,
                    "sign_time_ms": sign_res.sign_time_ms,
                    "serialize_time_ms": serialize_time_ms,
                    "rtt_ms": rtt_ms,
                    "net_baseline_rtt_ms": self.net_baseline_rtt_ms,
                    "receipt_ok": receipt_ok,
                    "mem_rss_kb": mem_rss_kb,
                    "mem_delta_kb": mem_delta_kb,
                    "cpu_user_ms": cpu_user_ms,
                    "cpu_sys_ms": cpu_sys_ms,
                }
                self.writer.writerow(row)
                self.csv_f.flush()

                # Realtime stats (consola)
                self.stats.add(
                    rtt_ms=rtt_ms,
                    sign_ms=sign_res.sign_time_ms,
                    stanza_bytes=stanza_bytes,
                )
                self.stats.maybe_print(prefix=f"[{alg_name}] ")

                # Pequeño pacing para no saturar
                await asyncio.sleep(0.05)

    def close(self):
        try:
            self.csv_f.close()
        except Exception:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Emisor benchmark con firmas PQC")
    parser.add_argument("--host", default=xmpp_env.get_xmpp_host())
    parser.add_argument("--port", type=int, default=xmpp_env.get_xmpp_port())
    parser.add_argument("--startup-timeout", type=int, default=20)
    parser.add_argument(
        "--iterations", type=int, default=100,
        help="Mensajes a enviar por algoritmo (default: 100)"
    )
    parser.add_argument(
        "--algorithms", choices=["ML-DSA", "SPHINCS", "all"], default="all",
        help="Familia de algoritmos a ejecutar (default: all)"
    )
    args = parser.parse_args()

    emisor_jid = xmpp_env.get_xmpp_jid("EMISOR")
    receptor_jid = xmpp_env.get_xmpp_jid("RECEPTOR")
    emisor_password = xmpp_env.get_xmpp_password("EMISOR")

    bot = EmisorBench(
        emisor_jid, emisor_password, receptor_jid,
        startup_timeout_s=args.startup_timeout,
        algs=_ALG_FAMILIES[args.algorithms],
        iterations=args.iterations,
    )
    bot.register_plugin("xep_0030")
    bot.register_plugin("xep_0184")  # Delivery Receipts

    bot.connect(host=args.host, port=args.port)
    bot.loop.call_later(args.startup_timeout, bot._startup_watchdog)
    bot.loop.run_forever()
    raise SystemExit(bot.exit_code)

import argparse
import csv
import os
import time
import psutil as _psutil
import slixmpp
from slixmpp.xmlstream import ET
from crypto.pqc_wrapper import PQCProvider
from metrics.realtime import RealtimeStats

NS = "urn:uma:tfm:pqc:0"

OUT_CSV = "artifacts/csv/receiver_metrics.csv"

_PROC = _psutil.Process()


class ReceptorBench(slixmpp.ClientXMPP):
    def __init__(self, jid, password, startup_timeout_s=20):
        super().__init__(jid, password)

        # Laboratorio local (sin TLS)
        self.use_tls = False
        self.use_ssl = False
        self.force_starttls = False
        self["feature_mechanisms"].unencrypted_plain = True

        self.boundjid.resource = "bench"
        self.startup_timeout_s = startup_timeout_s
        self.session_ready = False
        self.exit_code = 0

        self.pqc = PQCProvider()

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.on_message)
        self.add_event_handler("failed_auth", self.on_failed_auth)
        self.add_event_handler("connection_failed", self.on_connection_failed)
        self.add_event_handler("disconnected", self.on_disconnected)

        # CSV
        self.csv_f = open(OUT_CSV, "w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.csv_f, fieldnames=[
            "ts_unix",
            "from",
            "msg_id",
            "alg",
            "stanza_bytes",
            "body_bytes",
            "pk_b64_bytes",
            "sig_b64_bytes",
            "deserialize_time_ms",
            "verify_time_ms",
            "verify_ok",
            "cpu_user_ms",
            "cpu_sys_ms",
            "mem_rss_kb",
        ])
        self.writer.writeheader()
        self.stats = RealtimeStats(window=50)

    async def start(self, _):
        self.session_ready = True
        self.send_presence()
        await self.get_roster()
        print("ReceptorBench listo. Guardando en:", OUT_CSV)

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

    def on_message(self, msg):
        if msg["type"] not in ("chat", "normal"):
            return

        # Tamaño stanza recibida
        stanza_bytes = len(ET.tostring(msg.xml, encoding="utf-8"))
        body = msg["body"] or ""
        body_bytes = len(body.encode("utf-8"))

        # Extraer PQC (medir tiempo de deserialización)
        _t0_deser = time.perf_counter()
        pqc = msg.xml.find(f"{{{NS}}}pqc_auth")
        if pqc is None:
            # Aun así, si el emisor pidió receipt, respondemos:
            self._send_receipt_if_requested(msg)
            return

        alg = pqc.get("alg") or "UNKNOWN"
        sig_el = pqc.find(f"{{{NS}}}sig")
        pk_el = pqc.find(f"{{{NS}}}pk")
        sig_b64 = (sig_el.text or "").strip() if sig_el is not None else ""
        pk_b64 = (pk_el.text or "").strip() if pk_el is not None else ""
        deserialize_time_ms = (time.perf_counter() - _t0_deser) * 1000.0

        # Verificación con métricas CPU/memoria
        _t_cpu0 = _PROC.cpu_times()
        _mem0_kb = _PROC.memory_info().rss >> 10
        vr = self.pqc.verify_signature(alg, body.encode("utf-8"), sig_b64, pk_b64)
        _mem1_kb = _PROC.memory_info().rss >> 10
        _t_cpu1 = _PROC.cpu_times()
        cpu_user_ms = (_t_cpu1.user - _t_cpu0.user) * 1000.0
        cpu_sys_ms  = (_t_cpu1.system - _t_cpu0.system) * 1000.0
        mem_rss_kb  = _mem1_kb

        # Log
        row = {
            "ts_unix": time.time(),
            "from": str(msg["from"]),
            "msg_id": msg["id"],
            "alg": alg,
            "stanza_bytes": stanza_bytes,
            "body_bytes": body_bytes,
            "pk_b64_bytes": len(pk_b64.encode("ascii")),
            "sig_b64_bytes": len(sig_b64.encode("ascii")),
            "deserialize_time_ms": deserialize_time_ms,
            "verify_time_ms": vr.verify_time_ms,
            "verify_ok": int(bool(vr.ok)),
            "cpu_user_ms": cpu_user_ms,
            "cpu_sys_ms": cpu_sys_ms,
            "mem_rss_kb": mem_rss_kb,
        }
        self.writer.writerow(row)
        self.csv_f.flush()

        # Realtime stats (consola)
        self.stats.add(
            verify_ms=vr.verify_time_ms,
            stanza_bytes=stanza_bytes,
        )
        self.stats.maybe_print(prefix=f"[{alg}] ")


        # Responder receipt (RTT en el emisor)
        self._send_receipt_if_requested(msg)

    def _send_receipt_if_requested(self, msg):
        # Slixmpp XEP-0184: si el emisor lo pidió, contestamos.
        try:
            if msg["request_receipt"]:
                msg.reply().send_receipt(msg["id"])
        except Exception:
            # No matamos el receptor por receipts
            pass

    def close(self):
        try:
            self.csv_f.close()
        except Exception:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Receptor benchmark con firmas PQC")
    parser.add_argument("--host", default=os.getenv("XMPP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("XMPP_PORT", "5222")))
    parser.add_argument("--startup-timeout", type=int, default=20)
    args = parser.parse_args()

    bot = ReceptorBench("receptor@localhost", "123", startup_timeout_s=args.startup_timeout)
    bot.register_plugin("xep_0030")
    bot.register_plugin("xep_0184")  # Delivery Receipts

    bot.connect(host=args.host, port=args.port)
    bot.loop.call_later(args.startup_timeout, bot._startup_watchdog)
    bot.loop.run_forever()
    raise SystemExit(bot.exit_code)

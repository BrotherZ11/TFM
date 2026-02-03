import asyncio
import csv
import time
import slixmpp
from slixmpp.xmlstream import ET
from pqc_wrapper import PQCProvider

NS = "urn:uma:tfm:pqc:0"

OUT_CSV = "sender_metrics.csv"

# Algoritmos a probar
ALGS = [
    ("ML-DSA", "ML-DSA-65", 100),
    ("SPHINCS", "SPHINCS+-SHA2-128s-simple", 100),
]


class EmisorBench(slixmpp.ClientXMPP):
    def __init__(self, jid, password, recipient):
        super().__init__(jid, password)

        self.use_tls = False
        self.use_ssl = False
        self.force_starttls = False
        self["feature_mechanisms"].unencrypted_plain = True

        self.boundjid.resource = "bench"

        self.recipient = recipient
        self.pqc = PQCProvider()

        self.pending = {}  # msg_id -> (send_time_perf, future)

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("receipt_received", self.on_receipt)

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
            "sign_time_ms",
            "rtt_ms",
            "receipt_ok",
        ])
        self.writer.writeheader()

    async def start(self, _):
        self.send_presence()
        await self.get_roster()
        await asyncio.sleep(0.2)

        print("EmisorBench listo. Guardando en:", OUT_CSV)
        await self.run_benchmark()
        self.disconnect()

    def on_receipt(self, msg):
        # msg['receipt'] contiene el id del mensaje recibido
        msg_id = msg["receipt"]
        if msg_id in self.pending:
            t_send, fut = self.pending.pop(msg_id)
            rtt_ms = (time.perf_counter() - t_send) * 1000.0
            if not fut.done():
                fut.set_result(rtt_ms)

    async def run_benchmark(self):
        seq_global = 0

        for family, alg_name, n in ALGS:
            print(f"\n== Benchmark {family}: {alg_name} ({n} mensajes) ==")
            for i in range(1, n + 1):
                seq_global += 1
                body = f"[{family} #{i}] Mensaje benchmark UMA"
                body_bytes = len(body.encode("utf-8"))

                # Firmar + medir sign_time_ms
                sign_res = self.pqc.sign_message(alg_name, body.encode("utf-8"))

                # Construir mensaje
                msg = self.make_message(mto=self.recipient, mbody=body, mtype="chat")
                msg_id = msg["id"] = self.new_id()

                # Pedir delivery receipt (para RTT)
                msg["request_receipt"] = True

                # Añadir PQC XML como hijos (robusto)
                pqc_tag = ET.Element(f"{{{NS}}}pqc_auth")
                pqc_tag.set("alg", alg_name)

                sig_el = ET.SubElement(pqc_tag, f"{{{NS}}}sig")
                sig_el.text = sign_res.sig_b64

                pk_el = ET.SubElement(pqc_tag, f"{{{NS}}}pk")
                pk_el.text = sign_res.pk_b64

                msg.xml.append(pqc_tag)

                stanza_bytes = len(ET.tostring(msg.xml, encoding="utf-8"))
                pk_b64_bytes = len(sign_res.pk_b64.encode("ascii"))
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
                    "sign_time_ms": sign_res.sign_time_ms,
                    "rtt_ms": rtt_ms,
                    "receipt_ok": receipt_ok,
                }
                self.writer.writerow(row)
                self.csv_f.flush()

                # Pequeño pacing para no saturar
                await asyncio.sleep(0.05)

    def close(self):
        try:
            self.csv_f.close()
        except Exception:
            pass


if __name__ == "__main__":
    bot = EmisorBench("emisor@localhost", "123", "receptor@localhost")
    bot.register_plugin("xep_0030")
    bot.register_plugin("xep_0184")  # Delivery Receipts

    bot.connect(host="localhost", port=5222)
    bot.loop.run_forever()

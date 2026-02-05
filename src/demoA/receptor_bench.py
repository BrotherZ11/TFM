import csv
import time
import slixmpp
from slixmpp.xmlstream import ET
from crypto.pqc_wrapper import PQCProvider
from metrics.realtime import RealtimeStats

NS = "urn:uma:tfm:pqc:0"

OUT_CSV = "artifacts/csv/receiver_metrics.csv"


class ReceptorBench(slixmpp.ClientXMPP):
    def __init__(self, jid, password):
        super().__init__(jid, password)

        # Laboratorio local (sin TLS)
        self.use_tls = False
        self.use_ssl = False
        self.force_starttls = False
        self["feature_mechanisms"].unencrypted_plain = True

        self.boundjid.resource = "bench"

        self.pqc = PQCProvider()

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.on_message)

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
            "verify_time_ms",
            "verify_ok",
        ])
        self.writer.writeheader()
        self.stats = RealtimeStats(window=50)

    async def start(self, _):
        self.send_presence()
        await self.get_roster()
        print("ReceptorBench listo. Guardando en:", OUT_CSV)

    def on_message(self, msg):
        if msg["type"] not in ("chat", "normal"):
            return

        # Tamaño stanza recibida
        stanza_bytes = len(ET.tostring(msg.xml, encoding="utf-8"))
        body = msg["body"] or ""
        body_bytes = len(body.encode("utf-8"))

        # Extraer PQC
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

        # Verificación
        vr = self.pqc.verify_signature(alg, body.encode("utf-8"), sig_b64, pk_b64)

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
            "verify_time_ms": vr.verify_time_ms,
            "verify_ok": int(bool(vr.ok)),
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
    bot = ReceptorBench("receptor@localhost", "123")
    bot.register_plugin("xep_0030")
    bot.register_plugin("xep_0184")  # Delivery Receipts

    bot.connect(host="10.255.255.254", port=5222)
    bot.loop.run_forever()

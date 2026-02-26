import argparse
import csv
import json
import time
from pathlib import Path

import slixmpp
from slixmpp.xmlstream import ET

from demoB.keyring import ensure_keyring
from protocol.hybrid_protocol import (
    NS,
    b64d,
    derive_session_key,
    has_required_fields,
    kem_decapsulate,
    nonce16_b64,
    payload_reply,
    sign_payload,
    verify_payload,
)

INIT_REQUIRED = {"session_id", "from", "to", "kem_alg", "sig_alg", "nonce_a", "ct", "ts"}
FINAL_REQUIRED = {"session_id", "from", "to", "confirm", "nonce_b", "ts"}


class ReceptorHybrid(slixmpp.ClientXMPP):
    def __init__(self, jid, password, sig_alg, kem_alg, my_keyring, out_csv):
        super().__init__(jid, password)
        self.use_tls = False
        self.use_ssl = False
        self.force_starttls = False
        self["feature_mechanisms"].unencrypted_plain = True

        self.sig_alg = sig_alg
        self.kem_alg = kem_alg
        self.my_keys = ensure_keyring(my_keyring, sig_alg, kem_alg)

        self.sessions = {}

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.on_message)
        self.add_event_handler("disconnected", self.on_disconnected)

        Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
        self.csv_f = open(out_csv, "w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(
            self.csv_f,
            fieldnames=[
                "session_id",
                "verify_init_ms",
                "decap_ms",
                "sign_reply_ms",
                "stanza_reply_bytes",
                "ok",
            ],
        )
        self.writer.writeheader()

    async def start(self, _):
        self.send_presence()
        await self.get_roster()
        print("Receptor híbrido listo")

    def on_message(self, msg):
        init = msg.xml.find(f"{{{NS}}}init")
        if init is not None:
            self._handle_init(msg, init)
            return

        final = msg.xml.find(f"{{{NS}}}final")
        if final is not None:
            self._handle_final(msg, final)

    def _handle_init(self, msg, init):
        try:
            payload_raw = (init.findtext(f"{{{NS}}}payload") or "{}").strip()
            sig_b64 = (init.findtext(f"{{{NS}}}sig") or "").strip()
            pk_sig_b64 = (init.findtext(f"{{{NS}}}pk_sig") or "").strip()
            payload = json.loads(payload_raw)

            if not has_required_fields(payload, INIT_REQUIRED):
                return

            t0 = time.perf_counter()
            ok = verify_payload(self.sig_alg, pk_sig_b64, payload, sig_b64)
            t1 = time.perf_counter()
            if not ok:
                self._write_fail(payload.get("session_id", "unknown"))
                return

            t2 = time.perf_counter()
            ss_b64 = kem_decapsulate(self.kem_alg, b64d(self.my_keys["sk_kem"]), payload["ct"])
            t3 = time.perf_counter()

            nonce_b = nonce16_b64()
            p_reply = payload_reply(payload["session_id"], str(self.boundjid.bare), str(msg["from"].bare), payload["nonce_a"], nonce_b)
            t4 = time.perf_counter()
            signed = sign_payload(self.sig_alg, b64d(self.my_keys["sk_sig"]), p_reply)
            t5 = time.perf_counter()

            reply = self.make_message(mto=str(msg["from"].bare), mtype="chat")
            node = ET.Element(f"{{{NS}}}reply")
            ET.SubElement(node, f"{{{NS}}}payload").text = json.dumps(signed.payload, separators=(",", ":"), sort_keys=True)
            ET.SubElement(node, f"{{{NS}}}sig").text = signed.signature_b64
            ET.SubElement(node, f"{{{NS}}}pk_sig").text = self.my_keys["pk_sig"]
            reply.xml.append(node)

            stanza_bytes = len(ET.tostring(reply.xml, encoding="utf-8"))
            reply.send()

            _k = derive_session_key(ss_b64, payload["session_id"], payload["nonce_a"], nonce_b)
            self.sessions[payload["session_id"]] = {
                "from": str(msg["from"].bare),
                "established": False,
            }

            self.writer.writerow(
                {
                    "session_id": payload["session_id"],
                    "verify_init_ms": (t1 - t0) * 1000.0,
                    "decap_ms": (t3 - t2) * 1000.0,
                    "sign_reply_ms": (t5 - t4) * 1000.0,
                    "stanza_reply_bytes": stanza_bytes,
                    "ok": 1,
                }
            )
            self.csv_f.flush()
        except Exception as exc:
            print(f"Error procesando init: {exc}")
            self._write_fail("unknown")

    def _handle_final(self, msg, final):
        try:
            payload_raw = (final.findtext(f"{{{NS}}}payload") or "{}").strip()
            sig_b64 = (final.findtext(f"{{{NS}}}sig") or "").strip()
            pk_sig_b64 = (final.findtext(f"{{{NS}}}pk_sig") or "").strip()
            payload = json.loads(payload_raw)
            if not has_required_fields(payload, FINAL_REQUIRED):
                return
            if verify_payload(self.sig_alg, pk_sig_b64, payload, sig_b64):
                sid = payload.get("session_id")
                if sid in self.sessions:
                    self.sessions[sid]["established"] = True
                    print(f"Sesión establecida: {sid}")
        except Exception as exc:
            print(f"Error procesando final: {exc}")

    def _write_fail(self, session_id: str):
        self.writer.writerow(
            {
                "session_id": session_id,
                "verify_init_ms": float("nan"),
                "decap_ms": float("nan"),
                "sign_reply_ms": float("nan"),
                "stanza_reply_bytes": float("nan"),
                "ok": 0,
            }
        )
        self.csv_f.flush()

    def on_disconnected(self, _):
        if not self.csv_f.closed:
            self.csv_f.close()


def parse_args():
    parser = argparse.ArgumentParser(description="Receptor handshake híbrido PQ-XMPP")
    parser.add_argument("--jid", default="receptor@localhost")
    parser.add_argument("--password", default="123")
    parser.add_argument("--sig", default="ML-DSA-65")
    parser.add_argument("--kem", default="ML-KEM-768")
    parser.add_argument("--my-keyring", default="artifacts/keys/receptor_keys.json")
    parser.add_argument("--host", default="10.255.255.254")
    parser.add_argument("--port", type=int, default=5222)
    parser.add_argument("--out-csv", default="artifacts/csv/handshake_receiver.csv")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    bot = ReceptorHybrid(
        args.jid,
        args.password,
        args.sig,
        args.kem,
        my_keyring=args.my_keyring,
        out_csv=args.out_csv,
    )
    bot.connect(host=args.host, port=args.port)
    bot.loop.run_forever()

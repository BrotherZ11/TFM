import argparse
import asyncio
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
    kem_encapsulate,
    new_session_id,
    nonce16_b64,
    payload_final,
    payload_init,
    sign_payload,
    verify_payload,
)

INIT_REQUIRED = {"session_id", "from", "to", "kem_alg", "sig_alg", "nonce_a", "ct", "ts"}
REPLY_REQUIRED = {"session_id", "from", "to", "ack", "nonce_a", "nonce_b", "ts"}


class EmisorHybrid(slixmpp.ClientXMPP):
    def __init__(
        self,
        jid,
        password,
        recipient,
        sig_alg,
        kem_alg,
        my_keyring,
        peer_pub,
        out_csv,
        run_id,
        timeout_s,
    ):
        super().__init__(jid, password)
        self.use_tls = False
        self.use_ssl = False
        self.force_starttls = False
        self["feature_mechanisms"].unencrypted_plain = True

        self.recipient = recipient
        self.sig_alg = sig_alg
        self.kem_alg = kem_alg
        self.run_id = run_id
        self.timeout_s = timeout_s

        self.my_keys = ensure_keyring(my_keyring, sig_alg, kem_alg)
        self.peer_pub = json.loads(Path(peer_pub).read_text(encoding="utf-8"))

        self.session = {}
        self.reply_future = None

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.on_message)
        self.add_event_handler("disconnected", self.on_disconnected)

        Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
        self.csv_f = open(out_csv, "w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(
            self.csv_f,
            fieldnames=[
                "run_id",
                "session_id",
                "sig_alg",
                "kem_alg",
                "kem_encap_ms",
                "sign_init_ms",
                "verify_reply_ms",
                "sign_final_ms",
                "rtt_ms",
                "stanza_init_bytes",
                "ok",
            ],
        )
        self.writer.writeheader()

    async def start(self, _):
        self.send_presence()
        await self.get_roster()
        await asyncio.sleep(0.2)

        session_id = new_session_id()
        nonce_a = nonce16_b64()

        t_kem0 = time.perf_counter()
        ct_b64, ss_b64 = kem_encapsulate(self.kem_alg, self.peer_pub["pk_kem"])
        t_kem1 = time.perf_counter()

        p_init = payload_init(session_id, str(self.boundjid.bare), self.recipient, self.kem_alg, self.sig_alg, nonce_a, ct_b64)
        if not has_required_fields(p_init, INIT_REQUIRED):
            raise RuntimeError("Payload init incompleto")

        t0 = time.perf_counter()
        signed = sign_payload(self.sig_alg, b64d(self.my_keys["sk_sig"]), p_init)
        t1 = time.perf_counter()

        msg = self.make_message(mto=self.recipient, mtype="chat")
        init = ET.Element(f"{{{NS}}}init")
        init.set("sig_alg", self.sig_alg)
        init.set("kem_alg", self.kem_alg)
        init.set("key_id", "sender-key")

        ET.SubElement(init, f"{{{NS}}}payload").text = json.dumps(signed.payload, separators=(",", ":"), sort_keys=True)
        ET.SubElement(init, f"{{{NS}}}sig").text = signed.signature_b64
        ET.SubElement(init, f"{{{NS}}}pk_sig").text = self.my_keys["pk_sig"]
        msg.xml.append(init)

        stanza_bytes = len(ET.tostring(msg.xml, encoding="utf-8"))

        self.session = {
            "id": session_id,
            "ss_b64": ss_b64,
            "nonce_a": nonce_a,
            "sign_init_ms": (t1 - t0) * 1000.0,
            "kem_encap_ms": (t_kem1 - t_kem0) * 1000.0,
            "t_send": time.perf_counter(),
            "stanza_init_bytes": stanza_bytes,
            "sign_final_ms": float("nan"),
        }

        self.reply_future = asyncio.get_event_loop().create_future()
        msg.send()

        ok = 0
        try:
            ok = 1 if await asyncio.wait_for(self.reply_future, timeout=self.timeout_s) else 0
        except asyncio.TimeoutError:
            print("Timeout esperando pq:reply")
        finally:
            if ok == 0:
                self.writer.writerow(
                    {
                        "run_id": self.run_id,
                        "session_id": self.session.get("id"),
                        "sig_alg": self.sig_alg,
                        "kem_alg": self.kem_alg,
                        "kem_encap_ms": self.session.get("kem_encap_ms"),
                        "sign_init_ms": self.session.get("sign_init_ms"),
                        "verify_reply_ms": float("nan"),
                        "sign_final_ms": self.session.get("sign_final_ms"),
                        "rtt_ms": float("nan"),
                        "stanza_init_bytes": self.session.get("stanza_init_bytes"),
                        "ok": 0,
                    }
                )
                self.csv_f.flush()
            await asyncio.sleep(0.5)
            self.disconnect()

    def on_message(self, msg):
        reply = msg.xml.find(f"{{{NS}}}reply")
        if reply is None or self.reply_future is None or self.reply_future.done():
            return

        try:
            payload_raw = (reply.findtext(f"{{{NS}}}payload") or "{}").strip()
            sig_b64 = (reply.findtext(f"{{{NS}}}sig") or "").strip()
            pk_sig_b64 = (reply.findtext(f"{{{NS}}}pk_sig") or "").strip()
            payload = json.loads(payload_raw)

            if not has_required_fields(payload, REPLY_REQUIRED):
                self.reply_future.set_result(False)
                return

            t0 = time.perf_counter()
            ok = verify_payload(self.sig_alg, pk_sig_b64, payload, sig_b64)
            t1 = time.perf_counter()
            if not ok:
                print("Firma de pq:reply inválida")
                self.reply_future.set_result(False)
                return

            rtt_ms = (time.perf_counter() - self.session["t_send"]) * 1000.0
            nonce_b = payload["nonce_b"]
            _k = derive_session_key(self.session["ss_b64"], self.session["id"], self.session["nonce_a"], nonce_b)

            p_final = payload_final(self.session["id"], str(self.boundjid.bare), self.recipient, nonce_b)
            t_sign2_0 = time.perf_counter()
            signed_final = sign_payload(self.sig_alg, b64d(self.my_keys["sk_sig"]), p_final)
            t_sign2_1 = time.perf_counter()
            self.session["sign_final_ms"] = (t_sign2_1 - t_sign2_0) * 1000.0

            final_msg = self.make_message(mto=self.recipient, mtype="chat")
            final = ET.Element(f"{{{NS}}}final")
            ET.SubElement(final, f"{{{NS}}}payload").text = json.dumps(signed_final.payload, separators=(",", ":"), sort_keys=True)
            ET.SubElement(final, f"{{{NS}}}sig").text = signed_final.signature_b64
            ET.SubElement(final, f"{{{NS}}}pk_sig").text = self.my_keys["pk_sig"]
            final_msg.xml.append(final)
            final_msg.send()

            self.writer.writerow(
                {
                    "run_id": self.run_id,
                    "session_id": self.session["id"],
                    "sig_alg": self.sig_alg,
                    "kem_alg": self.kem_alg,
                    "kem_encap_ms": self.session["kem_encap_ms"],
                    "sign_init_ms": self.session["sign_init_ms"],
                    "verify_reply_ms": (t1 - t0) * 1000.0,
                    "sign_final_ms": self.session["sign_final_ms"],
                    "rtt_ms": rtt_ms,
                    "stanza_init_bytes": self.session["stanza_init_bytes"],
                    "ok": 1,
                }
            )
            self.csv_f.flush()
            print("Handshake completado:", self.session["id"])
            self.reply_future.set_result(True)
        except Exception as exc:
            print(f"Error procesando reply: {exc}")
            self.reply_future.set_result(False)

    def on_disconnected(self, _):
        if not self.csv_f.closed:
            self.csv_f.close()


def parse_args():
    parser = argparse.ArgumentParser(description="Emisor handshake híbrido PQ-XMPP")
    parser.add_argument("--jid", default="emisor@localhost")
    parser.add_argument("--password", default="123")
    parser.add_argument("--recipient", default="receptor@localhost")
    parser.add_argument("--sig", default="ML-DSA-65")
    parser.add_argument("--kem", default="ML-KEM-768")
    parser.add_argument("--my-keyring", default="artifacts/keys/emisor_keys.json")
    parser.add_argument("--peer-pub", default="artifacts/keys/receptor_pub.json")
    parser.add_argument("--host", default="10.255.255.254")
    parser.add_argument("--port", type=int, default=5222)
    parser.add_argument("--out-csv", default="artifacts/csv/handshake_sender.csv")
    parser.add_argument("--run-id", default="manual")
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    bot = EmisorHybrid(
        args.jid,
        args.password,
        args.recipient,
        args.sig,
        args.kem,
        my_keyring=args.my_keyring,
        peer_pub=args.peer_pub,
        out_csv=args.out_csv,
        run_id=args.run_id,
        timeout_s=args.timeout,
    )
    bot.connect(host=args.host, port=args.port)
    bot.loop.run_forever()

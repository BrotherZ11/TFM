import asyncio
import argparse
import base64
import csv
import os
import time
from pathlib import Path
import psutil as _psutil

import slixmpp
from slixmpp.xmlstream import ET

from crypto.pqc_wrapper import PQCProvider
from crypto.pqc_certificate import create_certificate, create_self_signed_certificate, certificate_to_pem
from metrics.realtime import RealtimeStats
from demo2_hybrid_kem_signed.protocol import NS_HYBRID, hello_message_to_sign, sha256_hex_from_b64

OUT_CSV = "artifacts/csv/hybrid_xmpp_sender_metrics.csv"

KEM_ALG = "ML-KEM-768"
SIG_ALGS = [
    ("ML-DSA", "ML-DSA-65", 30),
    ("SPHINCS", "SPHINCS+-SHA2-128s-simple", 30),
]

_PROC = _psutil.Process()


class EmisorHybridBench(slixmpp.ClientXMPP):
    def __init__(
        self,
        jid,
        password,
        recipient,
        verify_mode: str,
        issuer_dn: str,
        subject_base_dn: str,
        ca_secret_key_file: str | None,
        ca_public_key_file: str | None,
        qr_fingerprint_output_file: str | None,
        startup_timeout_s: int = 20,
        iterations: int = 30,
    ):
        super().__init__(jid, password)

        self.use_tls = False
        self.use_ssl = False
        self.force_starttls = False
        self["feature_mechanisms"].unencrypted_plain = True

        self.boundjid.resource = "hybrid-send"

        self.recipient = recipient
        self.pqc = PQCProvider()
        self.verify_mode = verify_mode
        self.startup_timeout_s = startup_timeout_s
        self.session_ready = False
        self.exit_code = 0
        self.issuer_dn = issuer_dn
        self.subject_base_dn = subject_base_dn
        self.ca_secret_key_file = ca_secret_key_file
        self.ca_public_key_file = ca_public_key_file
        self.qr_fingerprint_output_file = qr_fingerprint_output_file
        self.iterations = max(1, iterations)
        self.identity_by_alg = {}

        self.pending = {}

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.on_message)
        self.add_event_handler("failed_auth", self.on_failed_auth)
        self.add_event_handler("connection_failed", self.on_connection_failed)
        self.add_event_handler("disconnected", self.on_disconnected)

        os.makedirs("artifacts/csv", exist_ok=True)
        csv_exists = Path(OUT_CSV).exists() and Path(OUT_CSV).stat().st_size > 0
        self.csv_f = open(OUT_CSV, "a", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(
            self.csv_f,
            fieldnames=[
                "ts_unix",
                "alg_family",
                "sig_alg",
                "kem_alg",
                "seq",
                "nonce",
                "hello_stanza_bytes",
                "response_stanza_bytes",
                "kem_keygen_time_ms",
                "sign_time_ms",
                "serialize_time_ms",
                "decaps_time_ms",
                "rtt_ms",
                "sender_total_ms",
                "shared_secret_match",
                "ok",
                "verify_mode",
                "cert_fingerprint_sha256",
                "cert_bytes",
                "kem_pk_bytes",
                "kem_ct_bytes",
                "mem_rss_kb",
                "cpu_user_ms",
                "cpu_sys_ms",
            ],
        )
        if not csv_exists:
            self.writer.writeheader()
        self.stats = RealtimeStats(window=50)

    def _load_text_file(self, path: str | None) -> str | None:
        if not path:
            return None
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()

    def _build_identity_for_alg(self, sig_alg: str) -> dict:
        if sig_alg in self.identity_by_alg:
            return self.identity_by_alg[sig_alg]

        signer_kp = self.pqc.generate_signature_keypair(sig_alg)
        subject_dn = f"{self.subject_base_dn},OU={sig_alg}"

        ca_secret = self._load_text_file(self.ca_secret_key_file)
        ca_public = self._load_text_file(self.ca_public_key_file)

        if ca_secret and ca_public:
            cert = create_certificate(
                pqc=self.pqc,
                sig_alg=sig_alg,
                issuer_dn=self.issuer_dn,
                issuer_private_key_pem=ca_secret,
                subject_dn=subject_dn,
                subject_public_key_b64=signer_kp.public_key_b64,
                validity_days=365,
                is_ca=False,
            )
        else:
            cert = create_self_signed_certificate(
                pqc=self.pqc,
                sig_alg=sig_alg,
                subject_dn=subject_dn,
                subject_secret_key_b64=signer_kp.secret_key_b64,
                subject_public_key_b64=signer_kp.public_key_b64,
                validity_days=365,
                is_ca=False,
            )

        identity = {
            "secret_key_b64": signer_kp.secret_key_b64,
            "public_key_b64": signer_kp.public_key_b64,
            "cert": cert,
            "cert_fingerprint": cert["fingerprint_sha256"],
            "cert_pem": certificate_to_pem(cert),
        }
        self.identity_by_alg[sig_alg] = identity
        return identity

    def _write_qr_fingerprints(self):
        if not self.qr_fingerprint_output_file:
            return
        os.makedirs(os.path.dirname(self.qr_fingerprint_output_file), exist_ok=True)
        values = [v["cert_fingerprint"] for v in self.identity_by_alg.values()]
        with open(self.qr_fingerprint_output_file, "w", encoding="utf-8") as f:
            for value in sorted(set(values)):
                f.write(value + "\n")

    async def start(self, _):
        self.session_ready = True
        self.send_presence()
        await self.get_roster()
        await asyncio.sleep(0.2)

        print("EmisorHybridBench listo. CSV:", OUT_CSV)
        await self.run_benchmark()
        self.exit_code = 0
        self.disconnect()
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

    def on_message(self, msg):
        if msg["type"] not in ("chat", "normal"):
            return

        response = msg.xml.find(f"{{{NS_HYBRID}}}hybrid_response")
        if response is None:
            return

        nonce = response.get("nonce") or ""
        if nonce not in self.pending:
            return

        ciphertext_el = response.find(f"{{{NS_HYBRID}}}ciphertext")
        ss_hash_el = response.find(f"{{{NS_HYBRID}}}shared_secret_sha256")

        ciphertext_b64 = (ciphertext_el.text or "").strip() if ciphertext_el is not None else ""
        peer_hash = (ss_hash_el.text or "").strip() if ss_hash_el is not None else ""

        rec = self.pending.pop(nonce)

        rtt_ms = (time.perf_counter() - rec["send_t0"]) * 1000.0
        response_stanza_bytes = len(ET.tostring(msg.xml, encoding="utf-8"))

        ok = 0
        decaps_ms = float("nan")
        shared_secret_match = 0
        kem_ct_bytes = 0

        try:
            dec = self.pqc.decapsulate_secret(
                rec["kem_alg"], ciphertext_b64, rec["kem_secret_key_b64"]
            )
            decaps_ms = dec.decaps_time_ms
            own_hash = sha256_hex_from_b64(dec.shared_secret_b64)
            shared_secret_match = int(own_hash == peer_hash)
            ok = int(shared_secret_match == 1)
            kem_ct_bytes = len(base64.b64decode(ciphertext_b64)) if ciphertext_b64 else 0
        except Exception:
            ok = 0

        sender_total_ms = (time.perf_counter() - rec["t_total_start"]) * 1000.0

        if not rec["future"].done():
            rec["future"].set_result(
                {
                    "rtt_ms": rtt_ms,
                    "response_stanza_bytes": response_stanza_bytes,
                    "decaps_time_ms": decaps_ms,
                    "shared_secret_match": shared_secret_match,
                    "ok": ok,
                    "sender_total_ms": sender_total_ms,
                    "kem_ct_bytes": kem_ct_bytes,
                }
            )

    async def run_benchmark(self):
        for _, sig_alg, _ in SIG_ALGS:
            self._build_identity_for_alg(sig_alg)
        self._write_qr_fingerprints()

        for family, sig_alg, _ in SIG_ALGS:
            identity = self._build_identity_for_alg(sig_alg)
            n = self.iterations
            print(f"\n== {family} + {KEM_ALG} ({n} handshakes) ==")
            for i in range(1, n + 1):
                nonce = f"{family}-{i}-{time.time_ns()}"

                t_total_start = time.perf_counter()
                _t_cpu0 = _PROC.cpu_times()
                _mem0_kb = _PROC.memory_info().rss >> 10
                kem = self.pqc.generate_kem_keypair(KEM_ALG)
                sign = self.pqc.sign_with_secret_key(
                    sig_alg,
                    hello_message_to_sign(KEM_ALG, kem.public_key_b64, nonce, identity["cert_fingerprint"]),
                    identity["secret_key_b64"],
                    identity["public_key_b64"],
                )
                _mem1_kb = _PROC.memory_info().rss >> 10
                _t_cpu1 = _PROC.cpu_times()
                cpu_user_ms = (_t_cpu1.user - _t_cpu0.user) * 1000.0
                cpu_sys_ms  = (_t_cpu1.system - _t_cpu0.system) * 1000.0
                mem_rss_kb  = _mem1_kb

                kem_pk_bytes = len(base64.b64decode(kem.public_key_b64))

                # Serializar stanza hello con todos los campos PQC
                _t0_ser = time.perf_counter()
                msg = self.make_message(mto=self.recipient, mbody="[HYBRID_HELLO]", mtype="chat")
                msg["thread"] = nonce

                hello = ET.Element(f"{{{NS_HYBRID}}}hybrid_hello")
                hello.set("kem_alg", KEM_ALG)
                hello.set("sig_alg", sig_alg)
                hello.set("nonce", nonce)

                kem_pk_el = ET.SubElement(hello, f"{{{NS_HYBRID}}}kem_pk")
                kem_pk_el.text = kem.public_key_b64

                sig_el = ET.SubElement(hello, f"{{{NS_HYBRID}}}sig")
                sig_el.text = sign.sig_b64

                cert_el = ET.SubElement(hello, f"{{{NS_HYBRID}}}cert_pem")
                cert_el.text = identity["cert_pem"]

                cert_fp_el = ET.SubElement(hello, f"{{{NS_HYBRID}}}cert_fingerprint_sha256")
                cert_fp_el.text = identity["cert_fingerprint"]

                msg.xml.append(hello)

                hello_stanza_bytes = len(ET.tostring(msg.xml, encoding="utf-8"))
                serialize_time_ms = (time.perf_counter() - _t0_ser) * 1000.0

                fut = asyncio.get_event_loop().create_future()
                self.pending[nonce] = {
                    "future": fut,
                    "send_t0": time.perf_counter(),
                    "t_total_start": t_total_start,
                    "kem_alg": KEM_ALG,
                    "kem_secret_key_b64": kem.secret_key_b64,
                    "kem_pk_bytes": kem_pk_bytes,
                }

                msg.send()

                result = {
                    "rtt_ms": float("nan"),
                    "response_stanza_bytes": 0,
                    "decaps_time_ms": float("nan"),
                    "shared_secret_match": 0,
                    "ok": 0,
                    "sender_total_ms": float("nan"),
                    "kem_ct_bytes": 0,
                }
                try:
                    result = await asyncio.wait_for(fut, timeout=10.0)
                except asyncio.TimeoutError:
                    self.pending.pop(nonce, None)

                row = {
                    "ts_unix": time.time(),
                    "alg_family": family,
                    "sig_alg": sig_alg,
                    "kem_alg": KEM_ALG,
                    "seq": i,
                    "nonce": nonce,
                    "hello_stanza_bytes": hello_stanza_bytes,
                    "response_stanza_bytes": result["response_stanza_bytes"],
                    "kem_keygen_time_ms": kem.keygen_time_ms,
                    "sign_time_ms": sign.sign_time_ms,
                    "serialize_time_ms": serialize_time_ms,
                    "decaps_time_ms": result["decaps_time_ms"],
                    "rtt_ms": result["rtt_ms"],
                    "sender_total_ms": result["sender_total_ms"],
                    "shared_secret_match": result["shared_secret_match"],
                    "ok": result["ok"],
                    "verify_mode": self.verify_mode,
                    "cert_fingerprint_sha256": identity["cert_fingerprint"],
                    "cert_bytes": len(identity["cert_pem"].encode("utf-8")),
                    "kem_pk_bytes": kem_pk_bytes,
                    "kem_ct_bytes": result["kem_ct_bytes"],
                    "mem_rss_kb": mem_rss_kb,
                    "cpu_user_ms": cpu_user_ms,
                    "cpu_sys_ms": cpu_sys_ms,
                }
                self.writer.writerow(row)
                self.csv_f.flush()

                self.stats.add(
                    rtt_ms=result["rtt_ms"],
                    sign_ms=sign.sign_time_ms,
                    stanza_bytes=hello_stanza_bytes,
                )
                self.stats.maybe_print(prefix=f"[{sig_alg}] ")

                await asyncio.sleep(0.05)

    def close(self):
        try:
            self.csv_f.close()
        except Exception:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Emisor benchmark de handshake híbrido con verificación por certificado o QR")
    parser.add_argument("--verify-mode", choices=["cert", "qr"], default="cert")
    parser.add_argument("--issuer-dn", default="CN=UMA-PQC-CA,O=UMA,C=ES")
    parser.add_argument("--subject-base-dn", default="CN=emisor@localhost,O=UMA,C=ES")
    parser.add_argument("--ca-secret-key-file", default=None)
    parser.add_argument("--ca-public-key-file", default=None)
    parser.add_argument("--qr-fingerprint-output-file", default="artifacts/csv/trusted_qr_fingerprints.txt")
    parser.add_argument("--host", default=os.getenv("XMPP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("XMPP_PORT", "5222")))
    parser.add_argument("--startup-timeout", type=int, default=20)
    parser.add_argument(
        "--iterations", type=int, default=30,
        help="Handshakes a ejecutar por algoritmo de firma (default: 30)"
    )
    args = parser.parse_args()

    bot = EmisorHybridBench(
        "emisor@localhost",
        "123",
        "receptor@localhost",
        verify_mode=args.verify_mode,
        issuer_dn=args.issuer_dn,
        subject_base_dn=args.subject_base_dn,
        ca_secret_key_file=args.ca_secret_key_file,
        ca_public_key_file=args.ca_public_key_file,
        qr_fingerprint_output_file=args.qr_fingerprint_output_file,
        startup_timeout_s=args.startup_timeout,
        iterations=args.iterations,
    )
    bot.register_plugin("xep_0030")

    bot.connect(host=args.host, port=args.port)
    bot.loop.call_later(args.startup_timeout, bot._startup_watchdog)
    bot.loop.run_forever()
    raise SystemExit(bot.exit_code)

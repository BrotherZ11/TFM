import base64
import csv
import argparse
import os
import time
from pathlib import Path
import psutil as _psutil

import slixmpp
from slixmpp.xmlstream import ET

from crypto.pqc_wrapper import PQCProvider
from crypto.pqc_certificate import certificate_from_pem, verify_certificate
from metrics.realtime import RealtimeStats
from demo2_hybrid_kem_signed.protocol import NS_HYBRID, hello_message_to_sign, sha256_hex_from_b64, load_trusted_values

OUT_CSV = "artifacts/csv/hybrid_xmpp_receiver_metrics.csv"

_PROC = _psutil.Process()


class ReceptorHybridBench(slixmpp.ClientXMPP):
    def __init__(
        self,
        jid,
        password,
        verify_mode: str,
        trusted_fingerprints_file: str | None,
        trusted_issuer_public_keys_file: str | None,
        startup_timeout_s: int = 20,
    ):
        super().__init__(jid, password)

        self.use_tls = False
        self.use_ssl = False
        self.force_starttls = False
        self["feature_mechanisms"].unencrypted_plain = True

        self.boundjid.resource = "hybrid-recv"
        self.startup_timeout_s = startup_timeout_s
        self.session_ready = False
        self.exit_code = 0

        self.pqc = PQCProvider()
        self.verify_mode = verify_mode
        self.trusted_fingerprints_file = trusted_fingerprints_file
        self.trusted_issuer_public_keys_file = trusted_issuer_public_keys_file
        self.trusted_fingerprints = load_trusted_values(trusted_fingerprints_file)
        self.trusted_issuer_public_keys = load_trusted_values(trusted_issuer_public_keys_file)

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
                "from",
                "msg_id",
                "nonce",
                "kem_alg",
                "sig_alg",
                "hello_stanza_bytes",
                "response_stanza_bytes",
                "deserialize_time_ms",
                "verify_time_ms",
                "verify_ok",
                "cert_ok",
                "cert_reason",
                "cert_fingerprint_sha256",
                "encaps_time_ms",
                "receiver_total_ms",
                "cpu_user_ms",
                "cpu_sys_ms",
                "mem_rss_kb",
                "kem_pk_bytes",
                "kem_ct_bytes",
            ],
        )
        if not csv_exists:
            self.writer.writeheader()
        self.stats = RealtimeStats(window=50)

    async def start(self, _):
        self.session_ready = True
        self.send_presence()
        await self.get_roster()
        print("ReceptorHybridBench listo. CSV:", OUT_CSV)

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

        if self.verify_mode == "qr":
            self.trusted_fingerprints = load_trusted_values(self.trusted_fingerprints_file)
        elif self.verify_mode == "cert":
            self.trusted_issuer_public_keys = load_trusted_values(self.trusted_issuer_public_keys_file)

        hello = msg.xml.find(f"{{{NS_HYBRID}}}hybrid_hello")
        if hello is None:
            return

        t0 = time.perf_counter()

        # Deserialización: extraer todos los campos del stanza
        _t0_deser = time.perf_counter()
        kem_alg = hello.get("kem_alg") or ""
        sig_alg = hello.get("sig_alg") or ""
        nonce = hello.get("nonce") or ""

        kem_pk_el = hello.find(f"{{{NS_HYBRID}}}kem_pk")
        sig_el = hello.find(f"{{{NS_HYBRID}}}sig")
        cert_el = hello.find(f"{{{NS_HYBRID}}}cert_pem")
        if cert_el is None:
            cert_el = hello.find(f"{{{NS_HYBRID}}}cert_json")
        cert_fp_el = hello.find(f"{{{NS_HYBRID}}}cert_fingerprint_sha256")

        kem_pk_b64 = (kem_pk_el.text or "").strip() if kem_pk_el is not None else ""
        sig_b64 = (sig_el.text or "").strip() if sig_el is not None else ""
        cert_pem = (cert_el.text or "").strip() if cert_el is not None else ""
        cert_fingerprint_claim = (cert_fp_el.text or "").strip() if cert_fp_el is not None else ""

        hello_stanza_bytes = len(ET.tostring(msg.xml, encoding="utf-8"))
        deserialize_time_ms = (time.perf_counter() - _t0_deser) * 1000.0

        if not (kem_alg and sig_alg and nonce and kem_pk_b64 and sig_b64 and cert_pem and cert_fingerprint_claim):
            return

        cert = certificate_from_pem(cert_pem)
        cert_check = verify_certificate(
            cert,
            self.pqc,
            mode=self.verify_mode,
            trusted_fingerprints=self.trusted_fingerprints,
            trusted_issuer_public_keys=self.trusted_issuer_public_keys,
        )

        cert_ok = int(bool(cert_check.ok and cert_check.fingerprint_sha256 == cert_fingerprint_claim))
        cert_reason = cert_check.reason if cert_check.ok else cert_check.reason

        if cert_ok:
            vr = self.pqc.verify_signature(
                sig_alg,
                hello_message_to_sign(kem_alg, kem_pk_b64, nonce, cert_fingerprint_claim),
                sig_b64,
                cert["pqc_subject_public_key_b64"],
            )
        else:
            vr = self.pqc.verify_signature(sig_alg, b"", "", "")

        verify_ok = int(bool(vr.ok and cert_ok))
        enc_ms = float("nan")
        response_stanza_bytes = 0
        kem_ct_bytes = 0

        # Métricas CPU/memoria sobre el bloque crítico (verify + encaps)
        _t_cpu0 = _PROC.cpu_times()
        _mem0_kb = _PROC.memory_info().rss >> 10

        if verify_ok:
            enc = self.pqc.encapsulate_secret(kem_alg, kem_pk_b64)
            enc_ms = enc.encaps_time_ms
            kem_ct_bytes = len(base64.b64decode(enc.ciphertext_b64))

            response = self.make_message(mto=msg["from"], mbody="[HYBRID_RESPONSE]", mtype="chat")
            response["thread"] = nonce

            response_tag = ET.Element(f"{{{NS_HYBRID}}}hybrid_response")
            response_tag.set("kem_alg", kem_alg)
            response_tag.set("nonce", nonce)

            ct_el = ET.SubElement(response_tag, f"{{{NS_HYBRID}}}ciphertext")
            ct_el.text = enc.ciphertext_b64

            ss_el = ET.SubElement(response_tag, f"{{{NS_HYBRID}}}shared_secret_sha256")
            ss_el.text = sha256_hex_from_b64(enc.shared_secret_b64)

            response.xml.append(response_tag)
            response_stanza_bytes = len(ET.tostring(response.xml, encoding="utf-8"))
            response.send()

        _mem1_kb = _PROC.memory_info().rss >> 10
        _t_cpu1 = _PROC.cpu_times()
        cpu_user_ms = (_t_cpu1.user - _t_cpu0.user) * 1000.0
        cpu_sys_ms  = (_t_cpu1.system - _t_cpu0.system) * 1000.0
        mem_rss_kb  = _mem1_kb

        kem_pk_bytes = len(base64.b64decode(kem_pk_b64)) if kem_pk_b64 else 0

        receiver_total_ms = (time.perf_counter() - t0) * 1000.0

        row = {
            "ts_unix": time.time(),
            "from": str(msg["from"]),
            "msg_id": msg["id"],
            "nonce": nonce,
            "kem_alg": kem_alg,
            "sig_alg": sig_alg,
            "hello_stanza_bytes": hello_stanza_bytes,
            "response_stanza_bytes": response_stanza_bytes,
            "deserialize_time_ms": deserialize_time_ms,
            "verify_time_ms": vr.verify_time_ms,
            "verify_ok": verify_ok,
            "cert_ok": cert_ok,
            "cert_reason": cert_reason,
            "cert_fingerprint_sha256": cert_check.fingerprint_sha256,
            "encaps_time_ms": enc_ms,
            "receiver_total_ms": receiver_total_ms,
            "cpu_user_ms": cpu_user_ms,
            "cpu_sys_ms": cpu_sys_ms,
            "mem_rss_kb": mem_rss_kb,
            "kem_pk_bytes": kem_pk_bytes,
            "kem_ct_bytes": kem_ct_bytes,
        }
        self.writer.writerow(row)
        self.csv_f.flush()

        self.stats.add(verify_ms=vr.verify_time_ms, stanza_bytes=hello_stanza_bytes)
        self.stats.maybe_print(prefix=f"[{sig_alg}] ")

    def close(self):
        try:
            self.csv_f.close()
        except Exception:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Receptor benchmark de handshake híbrido con verificación por certificado o QR")
    parser.add_argument("--verify-mode", choices=["cert", "qr"], default="cert")
    parser.add_argument("--trusted-fingerprints-file", default="artifacts/csv/trusted_qr_fingerprints.txt")
    parser.add_argument("--trusted-issuer-public-keys-file", default=None)
    parser.add_argument("--host", default=os.getenv("XMPP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("XMPP_PORT", "5222")))
    parser.add_argument("--startup-timeout", type=int, default=20)
    args = parser.parse_args()

    bot = ReceptorHybridBench(
        "receptor@localhost",
        "123",
        verify_mode=args.verify_mode,
        trusted_fingerprints_file=args.trusted_fingerprints_file,
        trusted_issuer_public_keys_file=args.trusted_issuer_public_keys_file,
        startup_timeout_s=args.startup_timeout,
    )
    bot.register_plugin("xep_0030")

    bot.connect(host=args.host, port=args.port)
    bot.loop.call_later(args.startup_timeout, bot._startup_watchdog)
    bot.loop.run_forever()
    raise SystemExit(bot.exit_code)

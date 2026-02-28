import argparse
import base64
import csv
import hashlib
import json
import os
import time
from statistics import fmean

from crypto.pqc_wrapper import PQCProvider

KEM_ALG = "ML-KEM-768"
SIG_ALGS = [
    ("ML-DSA", "ML-DSA-65"),
    ("SPHINCS", "SPHINCS+-SHA2-128s-simple"),
]

SENDER_CSV = "artifacts/csv/kem_signed_sender_metrics.csv"
RECEIVER_CSV = "artifacts/csv/kem_signed_receiver_metrics.csv"


def _stable_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex_from_b64(secret_b64: str) -> str:
    secret = base64.b64decode(secret_b64.encode("ascii"))
    return hashlib.sha256(secret).hexdigest()


def _hello_message_to_sign(kem_alg: str, kem_pk_b64: str, nonce: str) -> bytes:
    payload = {
        "kem_alg": kem_alg,
        "kem_pk_b64": kem_pk_b64,
        "nonce": nonce,
        "type": "hello",
        "version": 1,
    }
    return _stable_json(payload)


def run_one_handshake(pqc: PQCProvider, sig_alg: str, kem_alg: str, iteration: int):
    nonce = f"i{iteration}-{time.time_ns()}"

    sender_total_t0 = time.perf_counter()

    # 1) Emisor: genera par ML-KEM efímero
    kem_kp = pqc.generate_kem_keypair(kem_alg)

    # 2) Emisor: firma su clave pública KEM
    hello_msg = _hello_message_to_sign(kem_alg, kem_kp.public_key_b64, nonce)
    sign_res = pqc.sign_message(sig_alg, hello_msg)

    hello_packet = {
        "type": "hello",
        "version": 1,
        "kem_alg": kem_alg,
        "sig_alg": sig_alg,
        "nonce": nonce,
        "kem_pk_b64": kem_kp.public_key_b64,
        "sig_b64": sign_res.sig_b64,
        "sig_pk_b64": sign_res.pk_b64,
    }

    hello_bytes = len(_stable_json(hello_packet))

    # 3) Receptor: verifica firma sobre la clave KEM y encapsula secreto
    receiver_total_t0 = time.perf_counter()

    vr = pqc.verify_signature(
        sig_alg,
        _hello_message_to_sign(hello_packet["kem_alg"], hello_packet["kem_pk_b64"], hello_packet["nonce"]),
        hello_packet["sig_b64"],
        hello_packet["sig_pk_b64"],
    )

    if vr.ok:
        enc_res = pqc.encapsulate_secret(kem_alg, hello_packet["kem_pk_b64"])
        verify_ok = 1
    else:
        enc_res = None
        verify_ok = 0

    response_packet = {
        "type": "response",
        "version": 1,
        "kem_alg": kem_alg,
        "nonce": nonce,
        "ciphertext_b64": enc_res.ciphertext_b64 if enc_res else "",
        "shared_secret_sha256": _sha256_hex_from_b64(enc_res.shared_secret_b64) if enc_res else "",
    }

    response_bytes = len(_stable_json(response_packet))
    receiver_total_ms = (time.perf_counter() - receiver_total_t0) * 1000.0

    # 4) Emisor: decapsula y valida que el secreto coincide
    if verify_ok:
        dec_res = pqc.decapsulate_secret(kem_alg, response_packet["ciphertext_b64"], kem_kp.secret_key_b64)
        sender_secret_hash = _sha256_hex_from_b64(dec_res.shared_secret_b64)
        shared_secret_match = int(sender_secret_hash == response_packet["shared_secret_sha256"])
        decaps_ms = dec_res.decaps_time_ms
        encaps_ms = enc_res.encaps_time_ms
    else:
        shared_secret_match = 0
        decaps_ms = float("nan")
        encaps_ms = float("nan")

    sender_total_ms = (time.perf_counter() - sender_total_t0) * 1000.0

    sender_row = {
        "ts_unix": time.time(),
        "iteration": iteration,
        "kem_alg": kem_alg,
        "sig_alg": sig_alg,
        "hello_bytes": hello_bytes,
        "response_bytes": response_bytes,
        "kem_keygen_ms": kem_kp.keygen_time_ms,
        "sign_time_ms": sign_res.sign_time_ms,
        "decaps_time_ms": decaps_ms,
        "sender_total_ms": sender_total_ms,
        "shared_secret_match": shared_secret_match,
    }

    receiver_row = {
        "ts_unix": time.time(),
        "iteration": iteration,
        "kem_alg": kem_alg,
        "sig_alg": sig_alg,
        "hello_bytes": hello_bytes,
        "response_bytes": response_bytes,
        "verify_time_ms": vr.verify_time_ms,
        "verify_ok": verify_ok,
        "encaps_time_ms": encaps_ms,
        "receiver_total_ms": receiver_total_ms,
    }

    return sender_row, receiver_row


def _mean(rows: list, key: str) -> float:
    values = [float(r[key]) for r in rows if str(r[key]).lower() != "nan"]
    if not values:
        return float("nan")
    return fmean(values)


def run_benchmark(iterations: int):
    os.makedirs("artifacts/csv", exist_ok=True)

    sender_fields = [
        "ts_unix",
        "iteration",
        "kem_alg",
        "sig_alg",
        "hello_bytes",
        "response_bytes",
        "kem_keygen_ms",
        "sign_time_ms",
        "decaps_time_ms",
        "sender_total_ms",
        "shared_secret_match",
    ]

    receiver_fields = [
        "ts_unix",
        "iteration",
        "kem_alg",
        "sig_alg",
        "hello_bytes",
        "response_bytes",
        "verify_time_ms",
        "verify_ok",
        "encaps_time_ms",
        "receiver_total_ms",
    ]

    all_sender_rows = []
    all_receiver_rows = []

    pqc = PQCProvider()

    with open(SENDER_CSV, "w", newline="", encoding="utf-8") as sender_f, open(
        RECEIVER_CSV, "w", newline="", encoding="utf-8"
    ) as receiver_f:
        sender_writer = csv.DictWriter(sender_f, fieldnames=sender_fields)
        receiver_writer = csv.DictWriter(receiver_f, fieldnames=receiver_fields)
        sender_writer.writeheader()
        receiver_writer.writeheader()

        for family, sig_alg in SIG_ALGS:
            print(f"\n== {family} + {KEM_ALG} | {iterations} iteraciones ==")
            family_sender = []
            family_receiver = []

            for i in range(1, iterations + 1):
                s_row, r_row = run_one_handshake(pqc, sig_alg=sig_alg, kem_alg=KEM_ALG, iteration=i)
                sender_writer.writerow(s_row)
                receiver_writer.writerow(r_row)

                family_sender.append(s_row)
                family_receiver.append(r_row)
                all_sender_rows.append(s_row)
                all_receiver_rows.append(r_row)

                if i % max(1, iterations // 5) == 0 or i == iterations:
                    print(
                        f"  iter {i}/{iterations} | sign={s_row['sign_time_ms']:.2f} ms | "
                        f"verify={r_row['verify_time_ms']:.2f} ms | "
                        f"encap={r_row['encaps_time_ms']:.2f} ms | "
                        f"decap={s_row['decaps_time_ms']:.2f} ms | "
                        f"match={s_row['shared_secret_match']}"
                    )

            print(
                "  medias -> "
                f"sign={_mean(family_sender, 'sign_time_ms'):.2f} ms, "
                f"verify={_mean(family_receiver, 'verify_time_ms'):.2f} ms, "
                f"encap={_mean(family_receiver, 'encaps_time_ms'):.2f} ms, "
                f"decap={_mean(family_sender, 'decaps_time_ms'):.2f} ms"
            )

    print("\nCSV generados:")
    print(" -", SENDER_CSV)
    print(" -", RECEIVER_CSV)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark de protocolo ML-KEM con clave firmada (ML-DSA/SPHINCS)")
    parser.add_argument("--iterations", type=int, default=20, help="Iteraciones por algoritmo de firma")
    args = parser.parse_args()

    run_benchmark(iterations=max(1, args.iterations))

"""
crypto_comparison_bench.py — Benchmark autónomo (sin XMPP) que compara:
  · Criptografía clásica: RSA-2048, ECDSA P-256, ECDH P-256 (como KEM)
  · PQC firmas:  ML-DSA-44, ML-DSA-65, ML-DSA-87
                 SPHINCS+-SHA2-128s-simple, SPHINCS+-SHA2-128f-simple
  · PQC KEM:     ML-KEM-512, ML-KEM-768, ML-KEM-1024

No requiere servidor XMPP. Mide keygen, sign/encaps, verify/decaps y tamaños.

Salida:
  artifacts/csv/sig_comparison_metrics.csv
  artifacts/csv/kem_comparison_metrics.csv

Uso:
  PYTHONPATH=src python src/metrics/crypto_comparison_bench.py [--iterations N] [--mode sig|kem|all]
"""

import argparse
import csv
import os
import time
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from oqs.oqs import KeyEncapsulation, Signature

# ─── Configuración de algoritmos ──────────────────────────────────────────────

SIG_ALGORITHMS = [
    # (family, name, alg_type)
    ("RSA",     "RSA-2048",                   "classical"),
    ("ECDSA",   "ECDSA-P256",                 "classical"),
    ("ML-DSA",  "ML-DSA-44",                  "pqc"),
    ("ML-DSA",  "ML-DSA-65",                  "pqc"),
    ("ML-DSA",  "ML-DSA-87",                  "pqc"),
    ("SPHINCS", "SPHINCS+-SHA2-128s-simple",  "pqc"),
    ("SPHINCS", "SPHINCS+-SHA2-128f-simple",  "pqc"),
]

KEM_ALGORITHMS = [
    # (family, name, alg_type)
    ("ECDH",   "ECDH-P256",   "classical"),
    ("ML-KEM", "ML-KEM-512",  "pqc"),
    ("ML-KEM", "ML-KEM-768",  "pqc"),
    ("ML-KEM", "ML-KEM-1024", "pqc"),
]

OUT_SIG_CSV = Path("artifacts/csv/sig_comparison_metrics.csv")
OUT_KEM_CSV = Path("artifacts/csv/kem_comparison_metrics.csv")

# Mensaje de prueba similar al body de una stanza XMPP en los benchmarks
MESSAGE = (
    b"Benchmark PQC TFM - Universidad de Malaga - "
    b"mensaje de prueba para comparativa criptografica post-cuantica"
)

# ─── Benchmarks de firma ──────────────────────────────────────────────────────

def _bench_rsa(message: bytes) -> dict:
    t0 = time.perf_counter()
    sk = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    keygen_ms = (time.perf_counter() - t0) * 1000.0

    pk       = sk.public_key()
    pk_bytes = len(pk.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    pad = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
    )

    t0 = time.perf_counter()
    sig = sk.sign(message, pad, hashes.SHA256())
    sign_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    try:
        pk.verify(sig, message, pad, hashes.SHA256())
        ok = 1
    except Exception:
        ok = 0
    verify_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "keygen_time_ms": keygen_ms,
        "sign_time_ms":   sign_ms,
        "verify_time_ms": verify_ms,
        "sig_bytes":      len(sig),
        "pk_bytes":       pk_bytes,
        "verify_ok":      ok,
    }


def _bench_ecdsa(message: bytes) -> dict:
    t0 = time.perf_counter()
    sk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    keygen_ms = (time.perf_counter() - t0) * 1000.0

    pk       = sk.public_key()
    pk_bytes = len(pk.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ))
    algo = ec.ECDSA(hashes.SHA256())

    t0 = time.perf_counter()
    sig = sk.sign(message, algo)
    sign_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    try:
        pk.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        ok = 1
    except Exception:
        ok = 0
    verify_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "keygen_time_ms": keygen_ms,
        "sign_time_ms":   sign_ms,
        "verify_time_ms": verify_ms,
        "sig_bytes":      len(sig),
        "pk_bytes":       pk_bytes,
        "verify_ok":      ok,
    }


def _bench_pqc_sig(alg_name: str, message: bytes) -> dict:
    # Keygen separado del signing para medir ambos de forma independiente
    with Signature(alg_name) as signer:
        t0 = time.perf_counter()
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
        keygen_ms = (time.perf_counter() - t0) * 1000.0

    with Signature(alg_name, secret_key=sk) as signer:
        t0 = time.perf_counter()
        sig = signer.sign(message)
        sign_ms = (time.perf_counter() - t0) * 1000.0

    with Signature(alg_name) as verifier:
        t0 = time.perf_counter()
        ok = verifier.verify(message, sig, pk)
        verify_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "keygen_time_ms": keygen_ms,
        "sign_time_ms":   sign_ms,
        "verify_time_ms": verify_ms,
        "sig_bytes":      len(sig),
        "pk_bytes":       len(pk),
        "verify_ok":      int(ok),
    }

# ─── Benchmarks KEM ───────────────────────────────────────────────────────────

def _bench_ecdh() -> dict:
    """ECDH P-256 modelado como KEM ephemeral: keygen Alice, encaps=Bob genera+derive,
    decaps=Alice deriva. Permite comparación directa con ML-KEM."""
    t0 = time.perf_counter()
    alice_sk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    alice_pk = alice_sk.public_key()
    keygen_ms = (time.perf_counter() - t0) * 1000.0

    pk_bytes = len(alice_pk.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ))

    # Encaps: Bob genera efímero y deriva secreto
    t0 = time.perf_counter()
    bob_sk  = ec.generate_private_key(ec.SECP256R1(), default_backend())
    bob_pk  = bob_sk.public_key()
    bob_shared = bob_sk.exchange(ec.ECDH(), alice_pk)
    encaps_ms = (time.perf_counter() - t0) * 1000.0

    # "Ciphertext" ECDH = clave pública efímera de Bob
    ct_bytes = len(bob_pk.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ))

    # Decaps: Alice deriva usando la clave efímera de Bob
    t0 = time.perf_counter()
    alice_shared = alice_sk.exchange(ec.ECDH(), bob_pk)
    decaps_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "keygen_time_ms":      keygen_ms,
        "encaps_time_ms":      encaps_ms,
        "decaps_time_ms":      decaps_ms,
        "pk_bytes":            pk_bytes,
        "ct_bytes":            ct_bytes,
        "shared_secret_match": int(alice_shared == bob_shared),
    }


def _bench_pqc_kem(alg_name: str) -> dict:
    with KeyEncapsulation(alg_name) as kem:
        t0 = time.perf_counter()
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        keygen_ms = (time.perf_counter() - t0) * 1000.0

    with KeyEncapsulation(alg_name) as kem:
        t0 = time.perf_counter()
        ct, shared_enc = kem.encap_secret(pk)
        encaps_ms = (time.perf_counter() - t0) * 1000.0

    with KeyEncapsulation(alg_name, sk) as kem:
        t0 = time.perf_counter()
        shared_dec = kem.decap_secret(ct)
        decaps_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "keygen_time_ms":      keygen_ms,
        "encaps_time_ms":      encaps_ms,
        "decaps_time_ms":      decaps_ms,
        "pk_bytes":            len(pk),
        "ct_bytes":            len(ct),
        "shared_secret_match": int(shared_enc == shared_dec),
    }

# ─── Ejecución ────────────────────────────────────────────────────────────────

SIG_FIELDS = [
    "ts_unix", "alg_family", "alg_name", "alg_type", "iteration",
    "keygen_time_ms", "sign_time_ms", "verify_time_ms",
    "sig_bytes", "pk_bytes", "verify_ok",
]

KEM_FIELDS = [
    "ts_unix", "alg_family", "alg_name", "alg_type", "iteration",
    "keygen_time_ms", "encaps_time_ms", "decaps_time_ms",
    "pk_bytes", "ct_bytes", "shared_secret_match",
]


def run_sig_benchmarks(iterations: int):
    os.makedirs(OUT_SIG_CSV.parent, exist_ok=True)
    with open(OUT_SIG_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SIG_FIELDS)
        w.writeheader()

        for family, name, alg_type in SIG_ALGORITHMS:
            print(f"\n== Firma: {name} ({iterations} iter) ==")
            for i in range(1, iterations + 1):
                try:
                    if name == "RSA-2048":
                        metrics = _bench_rsa(MESSAGE)
                    elif name == "ECDSA-P256":
                        metrics = _bench_ecdsa(MESSAGE)
                    else:
                        metrics = _bench_pqc_sig(name, MESSAGE)

                    w.writerow({
                        "ts_unix":    time.time(),
                        "alg_family": family,
                        "alg_name":   name,
                        "alg_type":   alg_type,
                        "iteration":  i,
                        **metrics,
                    })

                    if i % max(1, iterations // 5) == 0 or i == iterations:
                        print(
                            f"  {i:>4}/{iterations} | "
                            f"keygen={metrics['keygen_time_ms']:.3f} ms | "
                            f"sign={metrics['sign_time_ms']:.3f} ms | "
                            f"verify={metrics['verify_time_ms']:.3f} ms | "
                            f"sig={metrics['sig_bytes']} B | pk={metrics['pk_bytes']} B"
                        )
                except Exception as exc:
                    print(f"  SKIP {name} iter {i}: {exc}")

    print(f"\nCSV → {OUT_SIG_CSV}")


def run_kem_benchmarks(iterations: int):
    os.makedirs(OUT_KEM_CSV.parent, exist_ok=True)
    with open(OUT_KEM_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=KEM_FIELDS)
        w.writeheader()

        for family, name, alg_type in KEM_ALGORITHMS:
            print(f"\n== KEM: {name} ({iterations} iter) ==")
            for i in range(1, iterations + 1):
                try:
                    metrics = _bench_ecdh() if name == "ECDH-P256" else _bench_pqc_kem(name)
                    w.writerow({
                        "ts_unix":    time.time(),
                        "alg_family": family,
                        "alg_name":   name,
                        "alg_type":   alg_type,
                        "iteration":  i,
                        **metrics,
                    })

                    if i % max(1, iterations // 5) == 0 or i == iterations:
                        print(
                            f"  {i:>4}/{iterations} | "
                            f"keygen={metrics['keygen_time_ms']:.3f} ms | "
                            f"encaps={metrics['encaps_time_ms']:.3f} ms | "
                            f"decaps={metrics['decaps_time_ms']:.3f} ms | "
                            f"pk={metrics['pk_bytes']} B | ct={metrics['ct_bytes']} B"
                        )
                except Exception as exc:
                    print(f"  SKIP {name} iter {i}: {exc}")

    print(f"\nCSV → {OUT_KEM_CSV}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Benchmark comparativo: criptografía clásica vs PQC (sin XMPP)"
    )
    parser.add_argument(
        "--iterations", type=int, default=100,
        help="Iteraciones por algoritmo (default: 100)"
    )
    parser.add_argument(
        "--mode", choices=["sig", "kem", "all"], default="all",
        help="Qué benchmarks ejecutar: sig, kem o all (default: all)"
    )
    args = parser.parse_args()

    n = max(1, args.iterations)
    if args.mode in ("sig", "all"):
        run_sig_benchmarks(n)
    if args.mode in ("kem", "all"):
        run_kem_benchmarks(n)

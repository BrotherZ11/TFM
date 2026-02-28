import base64
from oqs.oqs import Signature
from oqs.oqs import KeyEncapsulation
import time
from dataclasses import dataclass


@dataclass
class SignResult:
    pk_b64: str
    sig_b64: str
    sign_time_ms: float


@dataclass
class VerifyResult:
    ok: bool
    verify_time_ms: float


@dataclass
class SignatureKeypairResult:
    public_key_b64: str
    secret_key_b64: str
    keygen_time_ms: float


@dataclass
class KEMKeypairResult:
    public_key_b64: str
    secret_key_b64: str
    keygen_time_ms: float


@dataclass
class EncapsulateResult:
    ciphertext_b64: str
    shared_secret_b64: str
    encaps_time_ms: float


@dataclass
class DecapsulateResult:
    shared_secret_b64: str
    decaps_time_ms: float


class PQCProvider:
    """
    - Firma/verifica con oqs-python.
    - Genera un keypair nuevo por mensaje (demo/bench).
      (En un diseño real, la clave pública sería identidad persistente.)
    """

    @staticmethod
    def sign_message(alg_name: str, message_bytes: bytes) -> SignResult:
        with Signature(alg_name) as sig:
            pk = sig.generate_keypair()
            t0 = time.perf_counter()
            signature = sig.sign(message_bytes)
            t1 = time.perf_counter()

        return SignResult(
            pk_b64=base64.b64encode(pk).decode("ascii"),
            sig_b64=base64.b64encode(signature).decode("ascii"),
            sign_time_ms=(t1 - t0) * 1000.0,
        )

    @staticmethod
    def verify_signature(alg_name: str, message_bytes: bytes, sig_b64: str, pk_b64: str) -> VerifyResult:
        try:
            sig_bytes = base64.b64decode(sig_b64.encode("ascii"))
            pk_bytes = base64.b64decode(pk_b64.encode("ascii"))
            with Signature(alg_name) as sig:
                t0 = time.perf_counter()
                ok = sig.verify(message_bytes, sig_bytes, pk_bytes)
                t1 = time.perf_counter()
            return VerifyResult(ok=ok, verify_time_ms=(t1 - t0) * 1000.0)
        except Exception:
            # si algo falla (b64, algoritmo, etc.)
            return VerifyResult(ok=False, verify_time_ms=float("nan"))

    @staticmethod
    def generate_signature_keypair(alg_name: str) -> SignatureKeypairResult:
        with Signature(alg_name) as sig:
            t0 = time.perf_counter()
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
            t1 = time.perf_counter()

        return SignatureKeypairResult(
            public_key_b64=base64.b64encode(public_key).decode("ascii"),
            secret_key_b64=base64.b64encode(secret_key).decode("ascii"),
            keygen_time_ms=(t1 - t0) * 1000.0,
        )

    @staticmethod
    def sign_with_secret_key(alg_name: str, message_bytes: bytes, secret_key_b64: str, public_key_b64: str) -> SignResult:
        secret_key = base64.b64decode(secret_key_b64.encode("ascii"))
        with Signature(alg_name, secret_key=secret_key) as sig:
            t0 = time.perf_counter()
            signature = sig.sign(message_bytes)
            t1 = time.perf_counter()

        return SignResult(
            pk_b64=public_key_b64,
            sig_b64=base64.b64encode(signature).decode("ascii"),
            sign_time_ms=(t1 - t0) * 1000.0,
        )

    @staticmethod
    def generate_kem_keypair(alg_name: str) -> KEMKeypairResult:
        with KeyEncapsulation(alg_name) as kem:
            t0 = time.perf_counter()
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            t1 = time.perf_counter()

        return KEMKeypairResult(
            public_key_b64=base64.b64encode(public_key).decode("ascii"),
            secret_key_b64=base64.b64encode(secret_key).decode("ascii"),
            keygen_time_ms=(t1 - t0) * 1000.0,
        )

    @staticmethod
    def encapsulate_secret(alg_name: str, public_key_b64: str) -> EncapsulateResult:
        public_key = base64.b64decode(public_key_b64.encode("ascii"))
        with KeyEncapsulation(alg_name) as kem:
            t0 = time.perf_counter()
            ciphertext, shared_secret = kem.encap_secret(public_key)
            t1 = time.perf_counter()

        return EncapsulateResult(
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            shared_secret_b64=base64.b64encode(shared_secret).decode("ascii"),
            encaps_time_ms=(t1 - t0) * 1000.0,
        )

    @staticmethod
    def decapsulate_secret(alg_name: str, ciphertext_b64: str, secret_key_b64: str) -> DecapsulateResult:
        ciphertext = base64.b64decode(ciphertext_b64.encode("ascii"))
        secret_key = base64.b64decode(secret_key_b64.encode("ascii"))

        with KeyEncapsulation(alg_name, secret_key) as kem:
            t0 = time.perf_counter()
            shared_secret = kem.decap_secret(ciphertext)
            t1 = time.perf_counter()

        return DecapsulateResult(
            shared_secret_b64=base64.b64encode(shared_secret).decode("ascii"),
            decaps_time_ms=(t1 - t0) * 1000.0,
        )

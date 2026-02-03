import base64
from oqs.oqs import Signature
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

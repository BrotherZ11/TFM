import hashlib
import json
from dataclasses import dataclass

NS_HYBRID = "urn:uma:tfm:pqc:hybrid:1"


@dataclass
class HybridHelloData:
    kem_alg: str
    sig_alg: str
    nonce: str
    kem_pk_b64: str
    sig_b64: str
    cert_json: str
    cert_fingerprint_sha256: str


def stable_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hello_message_to_sign(kem_alg: str, kem_pk_b64: str, nonce: str, cert_fingerprint_sha256: str) -> bytes:
    return stable_json_bytes(
        {
            "type": "hybrid_hello",
            "version": 1,
            "kem_alg": kem_alg,
            "kem_pk_b64": kem_pk_b64,
            "nonce": nonce,
            "cert_fingerprint_sha256": cert_fingerprint_sha256,
        }
    )


def sha256_hex_from_b64(secret_b64: str) -> str:
    secret = __import__("base64").b64decode(secret_b64.encode("ascii"))
    return hashlib.sha256(secret).hexdigest()


def load_trusted_values(path: str | None) -> set[str]:
    if not path:
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            out = set()
            for line in f:
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                out.add(value)
            return out
    except FileNotFoundError:
        return set()

    

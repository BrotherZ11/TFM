import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict

NS = "urn:tfm:pq:1"


@dataclass
class SignedPayload:
    payload: Dict[str, Any]
    signature_b64: str


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("ascii"))


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_payload(sig_alg: str, secret_key: bytes, payload: Dict[str, Any]) -> SignedPayload:
    # Import perezoso: facilita tests de utilidades puras sin dependencia oqs.
    from oqs.oqs import Signature

    to_sign = canonical_json_bytes(payload)
    with Signature(sig_alg, secret_key=secret_key) as sig:
        signature = sig.sign(to_sign)
    return SignedPayload(payload=payload, signature_b64=b64e(signature))


def verify_payload(sig_alg: str, public_key_b64: str, payload: Dict[str, Any], signature_b64: str) -> bool:
    from oqs.oqs import Signature

    to_verify = canonical_json_bytes(payload)
    signature = b64d(signature_b64)
    pk = b64d(public_key_b64)
    with Signature(sig_alg) as sig:
        return bool(sig.verify(to_verify, signature, pk))


def new_session_id() -> str:
    return str(uuid.uuid4())


def nonce16_b64() -> str:
    return b64e(uuid.uuid4().bytes)


def now_ms() -> int:
    return int(time.time() * 1000)


def kem_encapsulate(kem_alg: str, pk_kem_b64: str) -> tuple[str, str]:
    from oqs.oqs import KeyEncapsulation

    pk = b64d(pk_kem_b64)
    with KeyEncapsulation(kem_alg) as kem:
        ct, ss = kem.encap_secret(pk)
    return b64e(ct), b64e(ss)


def kem_decapsulate(kem_alg: str, sk_kem: bytes, ct_b64: str) -> str:
    from oqs.oqs import KeyEncapsulation

    ct = b64d(ct_b64)
    with KeyEncapsulation(kem_alg, secret_key=sk_kem) as kem:
        ss = kem.decap_secret(ct)
    return b64e(ss)


def derive_session_key(ss_b64: str, session_id: str, nonce_a_b64: str, nonce_b_b64: str) -> str:
    ss = b64d(ss_b64)
    salt = hashlib.sha256(f"{session_id}|{nonce_a_b64}|{nonce_b_b64}".encode("utf-8")).digest()
    prk = hmac.new(salt, ss, hashlib.sha256).digest()
    okm = hmac.new(prk, b"xmpp-pq-chat-v1", hashlib.sha256).digest()
    return b64e(okm)


def payload_init(
    session_id: str,
    from_jid: str,
    to_jid: str,
    kem_alg: str,
    sig_alg: str,
    nonce_a: str,
    ct_b64: str,
) -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "from": from_jid,
        "to": to_jid,
        "kem_alg": kem_alg,
        "sig_alg": sig_alg,
        "nonce_a": nonce_a,
        "ct": ct_b64,
        "ts": now_ms(),
    }


def payload_reply(session_id: str, from_jid: str, to_jid: str, nonce_a: str, nonce_b: str) -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "from": from_jid,
        "to": to_jid,
        "ack": "ok",
        "nonce_a": nonce_a,
        "nonce_b": nonce_b,
        "ts": now_ms(),
    }


def payload_final(session_id: str, from_jid: str, to_jid: str, nonce_b: str) -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "from": from_jid,
        "to": to_jid,
        "confirm": "ok",
        "nonce_b": nonce_b,
        "ts": now_ms(),
    }


def has_required_fields(payload: Dict[str, Any], required: set[str]) -> bool:
    return required.issubset(payload.keys())

import json
from pathlib import Path
from typing import Any, Dict

from protocol.hybrid_protocol import b64e


def ensure_keyring(path: str, sig_alg: str, kem_alg: str) -> Dict[str, Any]:
    from oqs.oqs import KeyEncapsulation, Signature

    p = Path(path)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))

    with Signature(sig_alg) as sig:
        pk_sig = sig.generate_keypair()
        sk_sig = sig.export_secret_key()

    with KeyEncapsulation(kem_alg) as kem:
        pk_kem = kem.generate_keypair()
        sk_kem = kem.export_secret_key()

    data = {
        "sig_alg": sig_alg,
        "kem_alg": kem_alg,
        "pk_sig": b64e(pk_sig),
        "sk_sig": b64e(sk_sig),
        "pk_kem": b64e(pk_kem),
        "sk_kem": b64e(sk_kem),
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data

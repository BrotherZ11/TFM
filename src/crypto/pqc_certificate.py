import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from crypto.pqc_wrapper import PQCProvider


CERT_SCHEMA = "pqc-x509-like-v1"
QR_PREFIX = "pqc-cert:v1:"


@dataclass
class CertificateValidationResult:
    ok: bool
    reason: str
    fingerprint_sha256: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso8601(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _tbs_for_signing(tbs: dict) -> bytes:
    return _canonical_json_bytes(tbs)


def certificate_fingerprint_sha256(cert: dict) -> str:
    payload = dict(cert)
    payload.pop("fingerprint_sha256", None)
    data = _canonical_json_bytes(payload)
    return hashlib.sha256(data).hexdigest()


def create_certificate(
    *,
    pqc: PQCProvider,
    sig_alg: str,
    issuer_dn: str,
    issuer_secret_key_b64: str,
    issuer_public_key_b64: str,
    subject_dn: str,
    subject_public_key_b64: str,
    validity_days: int = 365,
    is_ca: bool = False,
) -> dict:
    now = _utc_now()
    tbs = {
        "version": 3,
        "serial_number": uuid.uuid4().hex,
        "issuer_dn": issuer_dn,
        "subject_dn": subject_dn,
        "not_before": _iso8601(now),
        "not_after": _iso8601(now + timedelta(days=max(1, validity_days))),
        "sig_alg": sig_alg,
        "subject_public_key_b64": subject_public_key_b64,
        "extensions": {
            "basic_constraints": {"ca": bool(is_ca)},
            "key_usage": ["digitalSignature"],
            "subject_key_identifier": hashlib.sha256(subject_public_key_b64.encode("ascii")).hexdigest()[:32],
        },
    }

    sign_res = pqc.sign_with_secret_key(
        sig_alg,
        _tbs_for_signing(tbs),
        issuer_secret_key_b64,
        issuer_public_key_b64,
    )

    cert = {
        "schema": CERT_SCHEMA,
        "tbs": tbs,
        "signature_b64": sign_res.sig_b64,
        "issuer_public_key_b64": issuer_public_key_b64,
    }
    cert["fingerprint_sha256"] = certificate_fingerprint_sha256(cert)
    return cert


def create_self_signed_certificate(
    *,
    pqc: PQCProvider,
    sig_alg: str,
    subject_dn: str,
    subject_secret_key_b64: str,
    subject_public_key_b64: str,
    validity_days: int = 365,
    is_ca: bool = False,
) -> dict:
    return create_certificate(
        pqc=pqc,
        sig_alg=sig_alg,
        issuer_dn=subject_dn,
        issuer_secret_key_b64=subject_secret_key_b64,
        issuer_public_key_b64=subject_public_key_b64,
        subject_dn=subject_dn,
        subject_public_key_b64=subject_public_key_b64,
        validity_days=validity_days,
        is_ca=is_ca,
    )


def _parse_iso8601_utc(ts: str) -> Optional[datetime]:
    if not isinstance(ts, str):
        return None
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def verify_certificate_signature(cert: dict, pqc: PQCProvider) -> bool:
    try:
        if cert.get("schema") != CERT_SCHEMA:
            return False
        tbs = cert["tbs"]
        sig_alg = tbs["sig_alg"]
        signature_b64 = cert["signature_b64"]
        issuer_public_key_b64 = cert["issuer_public_key_b64"]
        vr = pqc.verify_signature(sig_alg, _tbs_for_signing(tbs), signature_b64, issuer_public_key_b64)
        return bool(vr.ok)
    except Exception:
        return False


def verify_certificate(
    cert: dict,
    pqc: PQCProvider,
    *,
    mode: str,
    trusted_fingerprints: Optional[set[str]] = None,
    trusted_issuer_public_keys: Optional[set[str]] = None,
) -> CertificateValidationResult:
    fingerprint = certificate_fingerprint_sha256(cert)

    if cert.get("schema") != CERT_SCHEMA:
        return CertificateValidationResult(False, "schema_no_soportado", fingerprint)

    tbs = cert.get("tbs", {})
    not_before = _parse_iso8601_utc(tbs.get("not_before", ""))
    not_after = _parse_iso8601_utc(tbs.get("not_after", ""))
    now = _utc_now()

    if not not_before or not not_after:
        return CertificateValidationResult(False, "validez_temporal_invalida", fingerprint)
    if now < not_before:
        return CertificateValidationResult(False, "cert_no_vigente_aun", fingerprint)
    if now > not_after:
        return CertificateValidationResult(False, "cert_expirado", fingerprint)

    if not verify_certificate_signature(cert, pqc):
        return CertificateValidationResult(False, "firma_cert_invalida", fingerprint)

    issuer_pk = cert.get("issuer_public_key_b64", "")
    if mode == "cert":
        if trusted_issuer_public_keys is not None and len(trusted_issuer_public_keys) > 0:
            if issuer_pk not in trusted_issuer_public_keys:
                return CertificateValidationResult(False, "issuer_no_confiable", fingerprint)
        return CertificateValidationResult(True, "ok", fingerprint)

    if mode == "qr":
        if not trusted_fingerprints:
            return CertificateValidationResult(False, "sin_huellas_qr_confiables", fingerprint)
        if fingerprint not in trusted_fingerprints:
            return CertificateValidationResult(False, "huella_qr_no_confiable", fingerprint)
        return CertificateValidationResult(True, "ok", fingerprint)

    return CertificateValidationResult(False, "modo_verificacion_desconocido", fingerprint)


def certificate_to_json(cert: dict) -> str:
    return json.dumps(cert, sort_keys=True, separators=(",", ":"))


def certificate_from_json(text: str) -> dict:
    return json.loads(text)


def certificate_to_qr_payload(cert: dict) -> str:
    raw = certificate_to_json(cert).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii")
    return QR_PREFIX + b64


def certificate_from_qr_payload(payload: str) -> dict:
    if not payload.startswith(QR_PREFIX):
        raise ValueError("QR payload no reconocido")
    b64 = payload[len(QR_PREFIX):]
    raw = base64.urlsafe_b64decode(b64.encode("ascii"))
    return certificate_from_json(raw.decode("utf-8"))

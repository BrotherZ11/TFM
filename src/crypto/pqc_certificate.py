import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from crypto.pqc_wrapper import PQCProvider


CERT_SCHEMA = "x509-pqc-v1"
QR_PREFIX = "pqc-cert:v1:"

OID_PQC_INFO = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")
OID_ISSUER_PUBKEY = ObjectIdentifier("1.3.6.1.4.1.55555.1.2")

_DN_ATTRS = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
}


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


def _dn_to_x509_name(dn: str) -> x509.Name:
    attrs: list[x509.NameAttribute] = []
    for raw_part in str(dn).split(","):
        part = raw_part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        oid = _DN_ATTRS.get(key.strip().upper())
        if oid is None:
            continue
        attrs.append(x509.NameAttribute(oid, value.strip()))
    if not attrs:
        attrs = [x509.NameAttribute(NameOID.COMMON_NAME, "unknown")]
    return x509.Name(attrs)


def _x509_to_pem(cert_obj: x509.Certificate) -> str:
    return cert_obj.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _x509_from_pem(cert_pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))


def _verify_x509_signature(cert_obj: x509.Certificate, issuer_public_key) -> bool:
    try:
        if isinstance(issuer_public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            issuer_public_key.verify(cert_obj.signature, cert_obj.tbs_certificate_bytes)
            return True
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                cert_obj.signature,
                cert_obj.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_obj.signature_hash_algorithm,
            )
            return True
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                cert_obj.signature,
                cert_obj.tbs_certificate_bytes,
                ec.ECDSA(cert_obj.signature_hash_algorithm),
            )
            return True
    except Exception:
        return False
    return False


def _extract_pqc_info(cert_obj: x509.Certificate) -> dict:
    try:
        ext = cert_obj.extensions.get_extension_for_oid(OID_PQC_INFO).value
        return json.loads(ext.value.decode("utf-8"))
    except Exception:
        return {}


def _extract_issuer_pubkey_b64(cert_obj: x509.Certificate) -> str:
    try:
        ext = cert_obj.extensions.get_extension_for_oid(OID_ISSUER_PUBKEY).value
        return base64.b64encode(ext.value).decode("ascii")
    except Exception:
        pub_der = cert_obj.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(pub_der).decode("ascii")


def _cert_not_valid_before_utc(cert_obj: x509.Certificate) -> datetime:
    value = getattr(cert_obj, "not_valid_before_utc", None)
    if value is not None:
        return value
    return cert_obj.not_valid_before.replace(tzinfo=timezone.utc)


def _cert_not_valid_after_utc(cert_obj: x509.Certificate) -> datetime:
    value = getattr(cert_obj, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert_obj.not_valid_after.replace(tzinfo=timezone.utc)


def certificate_fingerprint_sha256(cert: dict) -> str:
    der_b64 = cert.get("x509_der_b64")
    if isinstance(der_b64, str) and der_b64:
        return hashlib.sha256(base64.b64decode(der_b64.encode("ascii"))).hexdigest()
    cert_pem = cert.get("x509_pem") or cert.get("cert_pem") or ""
    cert_obj = _x509_from_pem(cert_pem)
    der = cert_obj.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def create_certificate(
    *,
    pqc: PQCProvider,
    sig_alg: str,
    issuer_dn: str,
    issuer_private_key_pem: str,
    subject_dn: str,
    subject_public_key_b64: str,
    validity_days: int = 365,
    is_ca: bool = False,
) -> dict:
    _ = pqc
    now = _utc_now()
    issuer_private_key = serialization.load_pem_private_key(
        issuer_private_key_pem.encode("utf-8"), password=None
    )
    issuer_pub_der = issuer_private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # X.509 requiere SubjectPublicKeyInfo clásico; se usa una clave Ed25519 auxiliar.
    subject_spki_key = ed25519.Ed25519PrivateKey.generate().public_key()

    pqc_info = {
        "sig_alg": sig_alg,
        "subject_public_key_b64": subject_public_key_b64,
    }

    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn_to_x509_name(subject_dn))
        .issuer_name(_dn_to_x509_name(issuer_dn))
        .public_key(subject_spki_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=max(1, validity_days)))
        .add_extension(x509.BasicConstraints(ca=bool(is_ca), path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=bool(is_ca),
                crl_sign=bool(is_ca),
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.UnrecognizedExtension(OID_PQC_INFO, _canonical_json_bytes(pqc_info)),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(OID_ISSUER_PUBKEY, issuer_pub_der),
            critical=False,
        )
    )

    algorithm = None if isinstance(issuer_private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)) else hashes.SHA256()
    cert_obj = builder.sign(private_key=issuer_private_key, algorithm=algorithm)
    cert_pem = _x509_to_pem(cert_obj)
    cert_der = cert_obj.public_bytes(serialization.Encoding.DER)

    cert = {
        "schema": CERT_SCHEMA,
        "x509_pem": cert_pem,
        "x509_der_b64": base64.b64encode(cert_der).decode("ascii"),
        "sig_alg": sig_alg,
        "subject_dn": subject_dn,
        "issuer_dn": issuer_dn,
        "pqc_subject_public_key_b64": subject_public_key_b64,
        "issuer_public_key_b64": base64.b64encode(issuer_pub_der).decode("ascii"),
        "not_before": _iso8601(now),
        "not_after": _iso8601(now + timedelta(days=max(1, validity_days))),
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
    _ = subject_secret_key_b64
    issuer_private_key = ed25519.Ed25519PrivateKey.generate()
    issuer_private_pem = issuer_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return create_certificate(
        pqc=pqc,
        sig_alg=sig_alg,
        issuer_dn=subject_dn,
        issuer_private_key_pem=issuer_private_pem,
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
    _ = pqc
    try:
        if cert.get("schema") != CERT_SCHEMA:
            return False
        cert_obj = _x509_from_pem(cert["x509_pem"])
        issuer_public_key_b64 = cert.get("issuer_public_key_b64") or _extract_issuer_pubkey_b64(cert_obj)
        issuer_pub = serialization.load_der_public_key(base64.b64decode(issuer_public_key_b64.encode("ascii")))
        return _verify_x509_signature(cert_obj, issuer_pub)
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
    cert_obj = _x509_from_pem(cert["x509_pem"])
    fingerprint = certificate_fingerprint_sha256(cert)

    if cert.get("schema") != CERT_SCHEMA:
        return CertificateValidationResult(False, "schema_no_soportado", fingerprint)

    not_before_dt = _cert_not_valid_before_utc(cert_obj)
    not_after_dt = _cert_not_valid_after_utc(cert_obj)

    not_before = _parse_iso8601_utc(_iso8601(not_before_dt))
    not_after = _parse_iso8601_utc(_iso8601(not_after_dt))
    now = _utc_now()

    if not not_before or not not_after:
        return CertificateValidationResult(False, "validez_temporal_invalida", fingerprint)
    if now < not_before:
        return CertificateValidationResult(False, "cert_no_vigente_aun", fingerprint)
    if now > not_after:
        return CertificateValidationResult(False, "cert_expirado", fingerprint)

    if not verify_certificate_signature(cert, pqc):
        return CertificateValidationResult(False, "firma_cert_invalida", fingerprint)

    issuer_pk = cert.get("issuer_public_key_b64") or _extract_issuer_pubkey_b64(cert_obj)
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
    return cert["x509_pem"]


def certificate_from_json(text: str) -> dict:
    return certificate_from_pem(text)


def certificate_to_pem(cert: dict) -> str:
    return cert["x509_pem"]


def certificate_from_pem(text: str) -> dict:
    cert_obj = _x509_from_pem(text)
    pqc_info = _extract_pqc_info(cert_obj)
    der = cert_obj.public_bytes(serialization.Encoding.DER)
    issuer_pub_b64 = _extract_issuer_pubkey_b64(cert_obj)

    out = {
        "schema": CERT_SCHEMA,
        "x509_pem": text,
        "x509_der_b64": base64.b64encode(der).decode("ascii"),
        "sig_alg": pqc_info.get("sig_alg", ""),
        "subject_dn": cert_obj.subject.rfc4514_string(),
        "issuer_dn": cert_obj.issuer.rfc4514_string(),
        "pqc_subject_public_key_b64": pqc_info.get("subject_public_key_b64", ""),
        "issuer_public_key_b64": issuer_pub_b64,
        "not_before": _iso8601(_cert_not_valid_before_utc(cert_obj)),
        "not_after": _iso8601(_cert_not_valid_after_utc(cert_obj)),
    }
    out["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
    return out


def certificate_to_qr_payload(cert: dict) -> str:
    raw = certificate_to_pem(cert).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii")
    return QR_PREFIX + b64


def certificate_from_qr_payload(payload: str) -> dict:
    if not payload.startswith(QR_PREFIX):
        raise ValueError("QR payload no reconocido")
    b64 = payload[len(QR_PREFIX):]
    raw = base64.urlsafe_b64decode(b64.encode("ascii"))
    return certificate_from_pem(raw.decode("utf-8"))

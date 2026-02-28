import argparse
import json
from pathlib import Path

from crypto.pqc_wrapper import PQCProvider
from crypto.pqc_certificate import (
    create_certificate,
    create_self_signed_certificate,
    certificate_to_json,
    certificate_to_qr_payload,
)


def write_text(path: str | None, text: str):
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def read_text(path: str | None) -> str | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8").strip()


def main():
    parser = argparse.ArgumentParser(description="Utilidad PKI PQC (perfil X.509-like) para ML-DSA/SPHINCS")
    parser.add_argument("--sig-alg", required=True, help="ML-DSA-65 o SPHINCS+-SHA2-128s-simple")
    parser.add_argument("--subject-dn", required=True, help="DN del sujeto, estilo X.509 (ej: CN=emisor@localhost,O=UMA,C=ES)")
    parser.add_argument("--issuer-dn", default=None, help="DN emisor; si se omite se genera self-signed")
    parser.add_argument("--validity-days", type=int, default=365)

    parser.add_argument("--ca-secret-key-file", default=None)
    parser.add_argument("--ca-public-key-file", default=None)

    parser.add_argument("--out-subject-secret-key-file", default=None)
    parser.add_argument("--out-subject-public-key-file", default=None)
    parser.add_argument("--out-cert-json-file", default=None)
    parser.add_argument("--out-qr-payload-file", default=None)

    args = parser.parse_args()

    pqc = PQCProvider()

    subject_kp = pqc.generate_signature_keypair(args.sig_alg)

    ca_secret = read_text(args.ca_secret_key_file)
    ca_public = read_text(args.ca_public_key_file)

    if ca_secret and ca_public and args.issuer_dn:
        cert = create_certificate(
            pqc=pqc,
            sig_alg=args.sig_alg,
            issuer_dn=args.issuer_dn,
            issuer_secret_key_b64=ca_secret,
            issuer_public_key_b64=ca_public,
            subject_dn=args.subject_dn,
            subject_public_key_b64=subject_kp.public_key_b64,
            validity_days=args.validity_days,
            is_ca=False,
        )
    else:
        cert = create_self_signed_certificate(
            pqc=pqc,
            sig_alg=args.sig_alg,
            subject_dn=args.subject_dn,
            subject_secret_key_b64=subject_kp.secret_key_b64,
            subject_public_key_b64=subject_kp.public_key_b64,
            validity_days=args.validity_days,
            is_ca=False,
        )

    cert_json = certificate_to_json(cert)
    qr_payload = certificate_to_qr_payload(cert)

    write_text(args.out_subject_secret_key_file, subject_kp.secret_key_b64)
    write_text(args.out_subject_public_key_file, subject_kp.public_key_b64)
    write_text(args.out_cert_json_file, cert_json)
    write_text(args.out_qr_payload_file, qr_payload)

    print(json.dumps(
        {
            "sig_alg": args.sig_alg,
            "subject_dn": args.subject_dn,
            "issuer_dn": cert["tbs"]["issuer_dn"],
            "fingerprint_sha256": cert["fingerprint_sha256"],
            "cert_json_bytes": len(cert_json.encode("utf-8")),
        },
        indent=2,
    ))


if __name__ == "__main__":
    main()

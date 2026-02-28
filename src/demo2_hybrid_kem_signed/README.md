# Demo 2 — Handshake híbrido ML-KEM autenticado con firmas PQC

Objetivo: establecer una clave simétrica usando `ML-KEM-768`, autenticando la clave pública efímera KEM con firma `ML-DSA` o `SPHINCS+`.

## Variante A: benchmark local (sin red)

Script:
- `src/demoA/kem_signed_bench.py`

Ejecución:
- `PYTHONPATH=src venv/bin/python src/demoA/kem_signed_bench.py --iterations 20`

CSV:
- `artifacts/csv/kem_signed_sender_metrics.csv`
- `artifacts/csv/kem_signed_receiver_metrics.csv`

## Variante B: handshake híbrido real sobre XMPP

Scripts:
- `src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py`
- `src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py`
- `src/demo2_hybrid_kem_signed/pqc_pki_tool.py`

Ejecución:
1. Receptor:
	- `PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py`
2. Emisor:
	- `PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py`

CSV:
- `artifacts/csv/hybrid_xmpp_sender_metrics.csv`
- `artifacts/csv/hybrid_xmpp_receiver_metrics.csv`

### Modos de verificación

1. **`cert`**: verificación por certificado PQC (perfil X.509-like)
	 - El emisor adjunta certificado firmado con `ML-DSA` o `SPHINCS+`.
	 - El receptor valida firma del certificado, validez temporal y firma del `HELLO` con la clave pública del certificado.

2. **`qr`**: verificación por huella (simulando escaneo QR)
	 - El receptor solo acepta certificados cuya huella esté en `trusted_qr_fingerprints.txt`.

Ejemplo `cert`:

- Receptor: `PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py --verify-mode cert`
- Emisor: `PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py --verify-mode cert`

Ejemplo `qr`:

- Emisor (genera huellas confiables):
	- `PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py --verify-mode qr --qr-fingerprint-output-file artifacts/csv/trusted_qr_fingerprints.txt`
- Receptor (valida por huella):
	- `PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py --verify-mode qr --trusted-fingerprints-file artifacts/csv/trusted_qr_fingerprints.txt`

### Herramienta PKI de apoyo

Generar certificado y payload QR:

- `PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/pqc_pki_tool.py --sig-alg ML-DSA-65 --subject-dn "CN=emisor@localhost,O=UMA,C=ES" --out-cert-json-file artifacts/csv/emisor_cert_mldsa.json --out-qr-payload-file artifacts/csv/emisor_cert_mldsa_qr.txt`

Notas de estandarización X.509 + PQC:

- `src/demo2_hybrid_kem_signed/x509_pqc_notes.md`

Métricas principales:
- tiempos de firma/verificación/encapsulación/desacapsulación
- RTT del handshake
- tamaño de stanzas `HELLO` y `RESPONSE`
- consistencia de secreto compartido (`shared_secret_match`)

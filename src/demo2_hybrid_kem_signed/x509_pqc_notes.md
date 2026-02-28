# X.509 + PQC (ML-DSA / SPHINCS) — Notas prácticas para el TFM

## 1) Qué es “estandarizado” hoy

- X.509 sigue siendo el estándar de certificados en PKI/TLS.
- El soporte operativo de firmas PQC en certificados X.509 depende de toolchain concreta (OpenSSL + proveedores PQC, p. ej. oqs-provider).
- En Python puro (`oqs-python`) no hay una API completa y estable para emitir/validar certificados X.509 DER con OIDs PQC de forma nativa.

## 2) Enfoque aplicado en este repositorio

En `Demo 2B` se usa un certificado **X.509 real** (PEM/DER) y se incorporan los campos PQC en extensiones privadas:

- Extensión OID privada con `sig_alg` (ML-DSA o SPHINCS+) y `subject_public_key_b64`.
- Extensión OID privada con la clave pública del emisor para validación autónoma en el benchmark.
- Verificación de validez temporal y firma X.509 en receptor.

Esto permite comparar dos modelos de confianza en el handshake:

1. `cert`: confianza por cadena/issuer (pinning de clave pública de emisor/CA).
2. `qr`: confianza por huella escaneada (pinning de fingerprint).

## 3) Relación con X.509 real

- La estructura de certificado es X.509 real y portable (`PEM/DER`).
- El material PQC viaja como metadato en extensiones privadas para mantener compatibilidad con `oqs-python`.
- Para una cadena PKI PQC totalmente estándar (OID PQC nativos en SPKI/firma de cert), la vía recomendada sigue siendo OpenSSL + oqs-provider.

## 4) Recomendación para la memoria

Indica explícitamente:

- “En Demo 2B se emplea certificado X.509 real con extensiones privadas para transportar identidad PQC”.
- “La comparación ML-DSA vs SPHINCS+ se realiza en el coste de firma/verificación del `HELLO` autenticado por el certificado”.
- “El análisis estadístico usa IC95 y Mann-Whitney U sobre los CSV de `hybrid_xmpp_*`”.

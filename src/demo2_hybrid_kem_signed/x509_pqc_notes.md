# X.509 + PQC (ML-DSA / SPHINCS) — Notas prácticas para el TFM

## 1) Qué es “estandarizado” hoy

- X.509 sigue siendo el estándar de certificados en PKI/TLS.
- El soporte operativo de firmas PQC en certificados X.509 depende de toolchain concreta (OpenSSL + proveedores PQC, p. ej. oqs-provider).
- En Python puro (`oqs-python`) no hay una API completa y estable para emitir/validar certificados X.509 DER con OIDs PQC de forma nativa.

## 2) Enfoque aplicado en este repositorio

Para no perder trazabilidad experimental y mantener compatibilidad con tu stack actual (`slixmpp` + `oqs-python`), se implementa un **perfil X.509-like**:

- Campos inspirados en TBSCertificate: `version`, `serial_number`, `issuer_dn`, `subject_dn`, `not_before`, `not_after`, `sig_alg`, `subject_public_key_b64`, `extensions`.
- Firma del bloque TBS con ML-DSA o SPHINCS+.
- Huella SHA-256 del certificado completo.

Esto permite comparar dos modelos de confianza en el handshake:

1. `cert`: confianza por cadena/issuer (pinning de clave pública de emisor/CA).
2. `qr`: confianza por huella escaneada (pinning de fingerprint).

## 3) Relación con X.509 real

- Este perfil **no reemplaza** un X.509 DER/PEM en producción.
- Sí es válido para el objetivo experimental del TFM: medir coste criptográfico y de transporte con semántica PKI equivalente.
- Si quieres una demo adicional “100% X.509 real con PQC”, la vía recomendada es OpenSSL + oqs-provider y validar fuera de Python con scripts de soporte.

## 4) Recomendación para la memoria

Indica explícitamente:

- “Se usa un perfil X.509-like firmado con PQC por limitaciones de soporte nativo en la pila Python actual”.
- “La semántica de verificación (validez temporal, identidad de emisor, pinning por huella) se preserva”.
- “Los resultados de rendimiento/overhead son representativos del coste PQC en la capa de mensajería”.

# X.509 + PQC (ML-DSA / SPHINCS) — Notas prácticas

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

## 4) Ejemplo de inspección con OpenSSL

Si se exporta el certificado PEM generado por `pqc_pki_tool.py`, puede inspeccionarse en texto con:

```bash
openssl x509 -in emisor_cert_mldsa.pem -text -noout
```

Un ejemplo representativo de salida sería:

```text
Certificate:
	Data:
		Version: 3 (0x2)
		Serial Number:
			52:8b:1d:9a:41:8f:8d:61:ef:32:87:bb:8e:10:5a:71
		Signature Algorithm: ED25519
		Issuer: CN = emisor@localhost, O = UMA, C = ES
		Validity
			Not Before: Jun 11 10:15:20 2026 GMT
			Not After : Jun 11 10:15:20 2027 GMT
		Subject: CN = emisor@localhost, O = UMA, C = ES
		Subject Public Key Info:
			Public Key Algorithm: ED25519
				ED25519 Public-Key:
				pub:
					9d:4a:1f:2c:73:8b:1a:5d:6e:41:2f:9c:87:aa:...
		X509v3 extensions:
			X509v3 Basic Constraints: critical
				CA:FALSE
			X509v3 Key Usage: critical
				Digital Signature
			1.3.6.1.4.1.55555.1.1:
				{"sig_alg":"ML-DSA-65","subject_public_key_b64":"tWQ8m0x...<recortado>...J7Q="}
			1.3.6.1.4.1.55555.1.2:
				0*0.....+..........0...*.H.=....<bytes DER/SPKI del emisor, recortados>
	Signature Algorithm: ED25519
	Signature Value:
		8a:63:1e:72:7f:5c:88:2e:41:5f:4b:66:d3:bb:74:...
```

Interpretación de los campos relevantes:

- `Subject Public Key Info` contiene una clave clásica auxiliar `Ed25519`, porque X.509 necesita un `SPKI` estándar soportado por la librería usada.
- `1.3.6.1.4.1.55555.1.1` es la extensión privada `OID_PQC_INFO`; guarda un JSON UTF-8 con `sig_alg` y `subject_public_key_b64`.
- `1.3.6.1.4.1.55555.1.2` es la extensión privada `OID_ISSUER_PUBKEY`; guarda en DER la clave pública del emisor usada para verificar la firma X.509.
- La firma del certificado sigue apareciendo como `ED25519`, porque en esta implementación la firma estructural del X.509 la realiza una clave clásica auxiliar, mientras que la identidad PQC viaja en extensiones privadas.

En otras palabras: el certificado es X.509 válido y portable, pero OpenSSL no interpreta semánticamente las extensiones PQC porque están codificadas como OID privados. Por eso muestra el JSON de forma casi legible en `1.3.6.1.4.1.55555.1.1` y un volcado de bytes en `1.3.6.1.4.1.55555.1.2`.

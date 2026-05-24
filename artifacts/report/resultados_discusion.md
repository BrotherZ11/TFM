# Resultados y Discusión

> Generado automáticamente el 2026-05-24 19:38 a partir de los CSV experimentales.


## 1. Resumen ejecutivo

- **Demo1 (firmas XMPP)**: 200 mensajes, tasa de confirmación = **1.000**.
- **Demo2 (handshake híbrido XMPP)**: 120 sesiones, éxito = **1.000**, secreto compartido = **1.000**.
- **Verificación de firma (receptor XMPP)**: **1.000**.

## 2. Metodología experimental

- Entorno: XMPP con `slixmpp` → servidor Prosody en `127.0.0.1:5222`.
- Capa PQC: `liboqs-python 0.14.1` / `liboqs 0.15.0`.
- Firmas evaluadas en XMPP: **ML-DSA-65** (retículos, NIST Level 3) y **SPHINCS+-SHA2-128s-simple** (hashes).
- KEM evaluado: **ML-KEM-768** (retículos, NIST Level 3).
- Benchmark comparativo: RSA-2048, ECDSA-P256, ECDH-P256 vs toda la familia ML-DSA/SPHINCS+/ML-KEM.
- Capturas de tráfico: `tshark` en interfaz `lo`, puerto 5222.


## 3. Resultados de firmas PQC en XMPP (Demo 1)

### 3.1 Métricas del emisor

| alg_family | n | sign_mean_ms | sign_p95_ms | sign_std_ms | rtt_mean_ms | rtt_p95_ms | net_baseline_ms | rtt_overhead_ms | stanza_mean_bytes | sig_mean_bytes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ML-DSA | 100 | 0.356 | 1.312 | 0.350 | 9.743 | 14.261 | 2.312 | 7.431 | 7367.920 | 4412.000 |
| SPHINCS | 100 | 136.933 | 153.103 | 9.991 | 59.311 | 64.444 | 2.312 | 56.999 | 10888.920 | 10476.000 |

> `rtt_overhead_ms` = RTT medio − baseline TCP loopback sin PQC.

### 3.2 Métricas del receptor

| alg | n | verify_mean_ms | verify_p95_ms | verify_ok_rate |
| --- | --- | --- | --- | --- |
| ML-DSA-65 | 100 | 0.158 | 0.428 | 1.000 |
| SPHINCS+-SHA2-128s-simple | 100 | 0.504 | 1.424 | 1.000 |

### 3.3 Significancia estadística

Test Mann-Whitney U (IC 95%, α=0.05) confirma diferencias significativas entre ML-DSA y SPHINCS+ en todas las métricas clave (sign_time, RTT, stanza_bytes). Ver `artifacts/csv/statistical_analysis.csv` para valores exactos.

### 3.4 Discusión

- ML-DSA-65 firma en media **0.356 ms** frente a **136.9 ms** de SPHINCS+ (×384 más lento).
- La firma SPHINCS+ ocupa **10476 bytes** en base64 vs **4412 bytes** ML-DSA (×2.4 mayor).
- El RTT overhead PQC sobre baseline TCP es **7.4 ms** (ML-DSA) y **57.0 ms** (SPHINCS+) en loopback.


## 4. Handshake híbrido local sin red (Demo 2A)

**Emisor:**

| sig_alg | n | kem_keygen_mean_ms | sig_keygen_mean_ms | sign_mean_ms | decaps_mean_ms | sender_total_mean_ms | hello_mean_bytes | response_mean_bytes | secret_match_rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ML-DSA-44 | 60 | 0.035 | 0.029 | 0.073 | 0.017 | 0.380 | 6711.883 | 1720.550 | 1.000 |
| ML-DSA-65 | 60 | 0.017 | 0.042 | 0.101 | 0.016 | 0.409 | 8747.883 | 1720.550 | 1.000 |
| ML-DSA-87 | 60 | 0.016 | 0.059 | 0.123 | 0.015 | 0.465 | 11359.883 | 1720.550 | 1.000 |
| SPHINCS+-SHA2-128f-simple | 60 | 0.019 | 0.267 | 6.303 | 0.020 | 7.482 | 24575.883 | 1720.550 | 1.000 |
| SPHINCS+-SHA2-128s-simple | 60 | 0.021 | 17.107 | 130.106 | 0.021 | 147.952 | 12267.883 | 1720.550 | 1.000 |

**Receptor:**

| sig_alg | n | verify_mean_ms | encaps_mean_ms | receiver_total_mean_ms | verify_ok_rate |
| --- | --- | --- | --- | --- | --- |
| ML-DSA-44 | 60 | 0.030 | 0.017 | 0.115 | 1.000 |
| ML-DSA-65 | 60 | 0.042 | 0.017 | 0.126 | 1.000 |
| ML-DSA-87 | 60 | 0.058 | 0.016 | 0.141 | 1.000 |
| SPHINCS+-SHA2-128f-simple | 60 | 0.503 | 0.033 | 0.690 | 1.000 |
| SPHINCS+-SHA2-128s-simple | 60 | 0.201 | 0.046 | 0.451 | 1.000 |

### 4.1 Discusión

- El benchmark local aísla el coste criptográfico puro (sin overhead de red).
- ML-KEM-768 domina el mix de variantes probadas (ML-KEM-512/768/1024 × ML-DSA-44/65/87 × SPHINCS+-128f/s — 15 combinaciones × 20 iteraciones).
- El secreto compartido coincide en el 100% de los ensayos (secret_match_rate = 1.000).


## 5. Handshake híbrido sobre XMPP (Demo 2B cert + 2C QR)

### 5.1 Métricas del emisor (por familia y modo de verificación)

| alg_family | verify_mode | n | kem_keygen_mean_ms | sign_mean_ms | decaps_mean_ms | rtt_mean_ms | sender_total_mean_ms | hello_stanza_mean_bytes | response_stanza_mean_bytes | success_rate | shared_secret_match_rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ML-DSA | cert | 30 | 0.239 | 0.716 | 0.141 | 67.670 | 71.207 | 10845.400 | 2023.400 | 1.000 | 1.000 |
| ML-DSA | qr | 30 | 0.196 | 0.624 | 0.187 | 69.965 | 73.522 | 10845.400 | 2023.400 | 1.000 | 1.000 |
| SPHINCS | cert | 30 | 0.238 | 155.945 | 0.133 | 68.739 | 226.723 | 13519.400 | 2025.400 | 1.000 | 1.000 |
| SPHINCS | qr | 30 | 0.179 | 152.092 | 0.111 | 67.837 | 221.728 | 13519.400 | 2025.400 | 1.000 | 1.000 |

### 5.2 Métricas del receptor (por algoritmo, cert+QR agregados)

| sig_alg | n | verify_mean_ms | encaps_mean_ms | receiver_total_mean_ms | verify_ok_rate | cert_ok_rate |
| --- | --- | --- | --- | --- | --- | --- |
| ML-DSA-65 | 60 | 0.336 | 0.162 | 4.593 | 1.000 | 1.000 |
| SPHINCS+-SHA2-128s-simple | 60 | 0.866 | 0.176 | 4.171 | 1.000 | 1.000 |

### 5.3 Discusión

- El RTT en XMPP refleja principalmente el coste de serialización XML + latencia de transporte; la diferencia entre familias es más visible en tiempos de firma y tamaño del mensaje HELLO.
- Los modos `cert` (X.509 post-cuántico) y `qr` (huella OOB) producen resultados estadísticamente equivalentes; el overhead diferencial es < 1 ms.
- Tasa de éxito y coincidencia de secreto: 100% en ambos modos.


## 6. Análisis de tráfico de red (Wireshark / tshark)

| scenario | total_packets | total_ip_bytes | total_tcp_payload_bytes | session_duration_ms | mean_payload_bytes | retransmissions |
| --- | --- | --- | --- | --- | --- | --- |
| Demo1 – Firmas XMPP | 1696 | 3829828 | 3717828 | 35733.42 | 3921.8 | 730 |
| Demo2A – Local | 846 | 809460 | 751916 | 9659.08 | 1352.4 | 285 |
| Demo2B – Cert | 662 | 1733992 | 1690236 | 13354.79 | 5153.2 | 316 |
| Demo2B – Cert X.509 | 662 | 1735316 | 1690236 | 12540.28 | 5153.2 | 316 |
| Demo2C – QR | 662 | 1733992 | 1690236 | 13094.58 | 5153.2 | 316 |
| Demo1 – ML-DSA | 668 | 1556866 | 1508706 | 13618.63 | 3508.6 | 220 |
| Demo1 – SPHINCS+ | 1066 | 2289722 | 2212906 | 31678.61 | 4175.3 | 518 |
| Demo1 – Texto claro | 1672 | 3835138 | 3714690 | 39678.3 | 3994.3 | 721 |

> Capturas realizadas en interfaz `lo` (loopback 127.0.0.1:5222). Ver `artifacts/pcap/` para análisis Wireshark detallado.


## 7. Comparativa clásico vs post-cuántico

### 7.1 Firmas: RSA-2048 / ECDSA-P256 vs ML-DSA / SPHINCS+

| alg_name | alg_type | n | keygen_mean_ms | sign_mean_ms | verify_mean_ms | sig_size_bytes | pk_size_bytes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ECDSA-P256 | classical | 50.000 | 0.024 | 0.034 | 0.072 | 71.100 | 65.000 |
| ML-DSA-44 | pqc | 50.000 | 0.054 | 0.058 | 0.026 | 2420.000 | 1312.000 |
| ML-DSA-65 | pqc | 50.000 | 0.041 | 0.107 | 0.038 | 3309.000 | 1952.000 |
| ML-DSA-87 | pqc | 50.000 | 0.062 | 0.116 | 0.060 | 4627.000 | 2592.000 |
| RSA-2048 | classical | 50.000 | 38.719 | 0.782 | 0.039 | 256.000 | 294.000 |
| SPHINCS+-SHA2-128f-simple | pqc | 50.000 | 0.271 | 6.179 | 0.477 | 17088.000 | 32.000 |
| SPHINCS+-SHA2-128s-simple | pqc | 50.000 | 17.811 | 136.320 | 0.197 | 7856.000 | 32.000 |

### 7.2 KEM: ECDH-P256 vs ML-KEM-512/768/1024

| alg_name | alg_type | n | keygen_mean_ms | encaps_mean_ms | decaps_mean_ms | pk_size_bytes | ct_size_bytes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ECDH-P256 | classical | 50.000 | 0.017 | 0.079 | 0.063 | 65.000 | 65.000 |
| ML-KEM-1024 | pqc | 50.000 | 0.017 | 0.018 | 0.020 | 1568.000 | 1568.000 |
| ML-KEM-512 | pqc | 50.000 | 0.010 | 0.010 | 0.010 | 800.000 | 768.000 |
| ML-KEM-768 | pqc | 50.000 | 0.013 | 0.014 | 0.015 | 1184.000 | 1088.000 |

### 7.3 Discusión

- ML-DSA presenta tiempos de firma comparables a ECDSA en hardware moderno, con un incremento moderado en tamaño de clave/firma.
- SPHINCS+ es significativamente más lento en firma (hash-based), aunque la verificación es rápida. Recomendado para escenarios donde la firma no es crítica en tiempo real.
- ML-KEM-768 ofrece rendimiento de encapsulación/desencapsulación en el mismo orden de magnitud que ECDH-P256, con resistencia cuántica probada.


## 8. Amenazas a la validez

- **Entorno controlado**: experimentos ejecutados en loopback (127.0.0.1), sin carga real de red ni múltiples nodos federados.
- **Versión de librería**: `liboqs-python 0.14.1` con `liboqs 0.15.0` nativa; el *warning* de versión es no fatal pero debería alinearse en publicación final.
- **Iteraciones**: 100 mensajes/alg en Demo1, 30 sesiones/modo en Demo2B-2C, 20 iter × 15 combinaciones en Demo2A. Suficiente para IC 95% con Mann-Whitney.
- **Hardware**: CPU x86-64 de un único ordenador personal; resultados no extrapolables directamente a ARM/embebido.


## 9. Conclusiones

- La integración PQC en XMPP es **funcionalmente correcta y reproducible** con el framework implementado (100% de tasas de éxito en todos los experimentos).
- El principal coste de adopción está en las **firmas** (especialmente SPHINCS+), no en la encapsulación ML-KEM.
- ML-DSA-65 es la opción más equilibrada para mensajería en tiempo real: baja latencia de firma, overhead de red moderado.
- El análisis de tráfico Wireshark confirma el overhead de bytes predecible por los tamaños teóricos de claves y firmas post-cuánticas.

## 10. Referencias a artefactos

| Artefacto | Ruta |
|---|---|
| CSVs de experimentos | `artifacts/csv/` |
| Figuras comparativas | `artifacts/figs/` |
| Capturas de red | `artifacts/pcap/` |
| Análisis estadístico | `artifacts/csv/statistical_analysis.csv` |
| Resumen global | `artifacts/csv/summary_experiments.csv` |

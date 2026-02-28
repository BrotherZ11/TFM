# Resultados y Discusión (Borrador automático)

> Documento generado automáticamente a partir de CSV experimentales del repositorio.

## 1. Resumen ejecutivo

- Handshake híbrido XMPP: tasa de éxito del emisor = **1.000**, coincidencia de secreto compartido = **1.000**, verificación de firma en receptor = **1.000**.


## 2. Metodología experimental

- Entorno de mensajería: XMPP con `slixmpp`.

- Capa PQC: `liboqs`/`oqs-python`.

- Firmas evaluadas: `ML-DSA-65` y `SPHINCS+-SHA2-128s-simple`.

- KEM evaluado: `ML-KEM-768`.

- Métricas: tiempos de firma/verificación/encapsulación/desencapsulación, RTT, tamaño de stanza/mensaje y tasa de éxito.


## 3. Resultados de firmas PQC en XMPP

### 3.1 Métricas del emisor

| alg_family | n | sign_mean_ms | sign_p95_ms | rtt_mean_ms | stanza_mean_bytes | sig_mean_bytes |
| --- | --- | --- | --- | --- | --- | --- |
| SPHINCS | 100 | 175.524 | 183.251 | 48.450 | 10888.920 | 10476.000 |


### 3.2 Métricas del receptor

| alg_family | n | verify_mean_ms | verify_p95_ms | verify_ok_rate |
| --- | --- | --- | --- | --- |
| SPHINCS | 100 | 0.299 | 0.360 | 1.000 |


### 3.3 Discusión

- SPHINCS+ incrementa el tamaño de firma y, por arrastre, el tamaño de stanza y el coste de firma.

- En el receptor, la verificación se mantiene en orden bajo, con tasa de validez cercana a 1.


## 4. Handshake híbrido local (sin red)

| sig_alg | n | keygen_mean_ms | sign_mean_ms | decaps_mean_ms | sender_total_mean_ms | hello_mean_bytes | response_mean_bytes | secret_match_rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ML-DSA-65 | 3 | 0.190 | 0.119 | 0.017 | 0.664 | 8747.000 | 1649.000 | 1.000 |
| SPHINCS+-SHA2-128s-simple | 3 | 0.022 | 128.807 | 0.020 | 146.451 | 12267.000 | 1649.000 | 1.000 |


| sig_alg | n | verify_mean_ms | encaps_mean_ms | receiver_total_mean_ms | verify_ok_rate |
| --- | --- | --- | --- | --- | --- |
| ML-DSA-65 | 3 | 0.045 | 0.025 | 0.126 | 1.000 |
| SPHINCS+-SHA2-128s-simple | 3 | 0.193 | 0.043 | 0.323 | 1.000 |



## 5. Handshake híbrido sobre XMPP

### 5.1 Métricas del emisor

| alg_family | n | keygen_mean_ms | sign_mean_ms | decaps_mean_ms | rtt_mean_ms | hello_stanza_mean_bytes | response_stanza_mean_bytes | success_rate | shared_secret_match_rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ML-DSA | 30 | 0.135 | 0.361 | 0.085 | 60.017 | 9047.400 | 2023.400 | 1.000 | 1.000 |
| SPHINCS | 30 | 0.121 | 126.722 | 0.107 | 63.970 | 12569.400 | 2025.400 | 1.000 | 1.000 |


### 5.2 Métricas del receptor

| sig_alg | n | verify_mean_ms | encaps_mean_ms | receiver_total_mean_ms | verify_ok_rate |
| --- | --- | --- | --- | --- | --- |
| ML-DSA-65 | 30 | 0.217 | 0.108 | 1.237 | 1.000 |
| SPHINCS+-SHA2-128s-simple | 30 | 0.827 | 0.133 | 2.039 | 1.000 |


### 5.3 Discusión

- En XMPP real, el RTT medio refleja principalmente coste de red/procesado de stanza; la diferencia entre familias aparece más fuerte en firma y tamaño de `HELLO`.

- Las tasas de éxito observadas sostienen la viabilidad funcional del protocolo híbrido en entorno de laboratorio.


## 6. Comparativa retículos vs hashes

- **Eficiencia temporal**: ML-DSA presenta menor latencia de firma que SPHINCS+ en las corridas actuales.

- **Sobrecarga de red**: SPHINCS+ incrementa tamaño de firma y, por tanto, tamaño de stanza.

- **Robustez funcional**: el handshake híbrido firmado completa correctamente en los ensayos disponibles con alta tasa de validación.


## 7. Amenazas a la validez

- Entorno de laboratorio (misma infraestructura, carga de red controlada).

- Dependencia de versión `liboqs`/`oqs-python`; conviene alinear versiones para publicación final.

- Resultados sujetos a variabilidad por CPU/carga de sistema y número de iteraciones.


## 8. Conclusiones

- La integración PQC en XMPP es factible y reproducible con el framework implementado.

- El principal coste de adopción en este escenario está en firmas (especialmente SPHINCS+), no en encapsulación ML-KEM.

- El sistema permite cuantificar objetivamente latencia, overhead de mensaje y éxito del protocolo híbrido.


## 9. Referencias a artefactos

- CSV: `artifacts/csv/`

- Figuras: `artifacts/figs/`

- Capturas de red: `artifacts/pcap/`

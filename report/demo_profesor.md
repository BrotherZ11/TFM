# Guion de demo para el profesor

## 1. Objetivo de la reunión

La demo debe transmitir tres ideas con claridad:

1. El proyecto no es solo una prueba de librería, sino una integración experimental de criptografía post-cuántica en mensajería XMPP.
2. Hay implementación funcional, medición reproducible y análisis comparativo.
3. Ya existe una base sólida para discutir mejoras técnicas y alcance final del TFM.

## 2. Mensaje principal que debes defender

La idea central es:

> He implementado un entorno experimental que integra firmas PQC y un handshake híbrido autenticado sobre XMPP, he medido coste temporal y sobrecarga en tamaño, y he comparado ML-DSA frente a SPHINCS+ con resultados estadísticamente analizables.

Si necesitas una versión más corta:

> El proyecto demuestra cómo llevar primitivas PQC a un flujo de mensajería realista, midiendo impacto en latencia, tamaño de mensajes y coste criptográfico.

## 3. Estructura recomendada de la exposición

Orden recomendado para una reunión de 12 a 20 minutos:

### Bloque 1. Problema y motivación

Explica esto en 1 minuto:

- XMPP aporta un canal de mensajería realista y conocido.
- La motivación es estudiar qué ocurre al introducir mecanismos post-cuánticos en ese canal.
- No solo interesa si funciona, sino cuánto cuesta en tiempo, tamaño y complejidad operativa.

### Bloque 2. Qué has implementado

Explica esto en 2 a 3 minutos:

- Demo 1: firma y verificación de stanzas XMPP con ML-DSA y SPHINCS+.
- Demo 2A: handshake híbrido local con ML-KEM autenticado mediante firma PQC.
- Demo 2B: handshake híbrido real sobre XMPP con verificación por certificado X.509.
- Demo 2C: variante de confianza por huella, simulando validación por QR.
- Demo 3: análisis de métricas, gráficas y comparación estadística.

### Bloque 3. Cómo está organizado el sistema

Explica esto en 2 minutos:

- La capa reutilizable está en src/crypto/pqc_wrapper.py.
- Ahí encapsulas firma, verificación, generación de claves, encapsulación y desacapsulación usando oqs-python.
- Las demos usan esa capa para no duplicar lógica criptográfica.
- En XMPP, el emisor inserta datos PQC en la stanza XML y el receptor extrae y verifica.
- En el handshake híbrido, el emisor firma el HELLO, el receptor valida identidad y después encapsula el secreto compartido.

### Bloque 4. Demo en vivo

Haz una ejecución breve y controlada:

1. Enseña que existe automatización completa con scripts/run_all_demos.sh.
2. Ejecuta una demo corta en vivo, preferiblemente Demo 2B en modo cert, porque es la que mejor sintetiza identidad, intercambio de clave y transporte real sobre XMPP.
3. Después muestra los CSV y una o dos gráficas ya generadas.

### Bloque 5. Resultados y lectura crítica

Explica esto en 3 a 4 minutos:

- ML-DSA es claramente más ligero en firma y tamaño que SPHINCS+.
- SPHINCS+ sigue siendo funcional, pero penaliza mucho más el rendimiento y el tamaño de las stanzas.
- En entorno XMPP, parte de la latencia ya viene de la red y del propio protocolo, por lo que no todo el coste total es puramente criptográfico.
- Aun así, la diferencia en firma y tamaño sí se ve de forma muy clara.

### Bloque 6. Qué mejorarías

Cierra con espíritu crítico:

- Persistencia de identidades y claves en lugar de regenerarlas en escenarios de benchmark.
- Integración PKI PQC más estándar con toolchain OpenSSL + oqs-provider.
- Más repeticiones controladas y mejor aislamiento experimental.
- Comparación con baseline clásico para cuantificar el sobrecoste PQC frente a esquemas no PQC.
- Automatización más robusta del entorno XMPP para facilitar reproducibilidad completa.

## 4. Qué enseñar exactamente en pantalla

Secuencia recomendada:

1. README principal para situar el repositorio.
2. scripts/run_all_demos.sh para mostrar que el flujo completo está automatizado.
3. src/crypto/pqc_wrapper.py para explicar la abstracción criptográfica reutilizable.
4. src/demo2_hybrid_kem_signed/protocol.py para explicar el mensaje HELLO firmado y el secreto compartido.
5. Ejecución en terminal de la demo elegida.
6. artifacts/csv/summary_experiments.csv para enseñar resultados tabulados.
7. artifacts/csv/statistical_analysis.csv para justificar que no es una observación anecdótica.
8. artifacts/figs/hybrid_xmpp_box_sign_ms.png y artifacts/figs/hybrid_xmpp_box_rtt_ms.png para cerrar visualmente.

## 5. Demo recomendada en vivo

## Opción preferida: Demo 2B en modo cert

Es la mejor para enseñar valor técnico porque combina:

- transporte XMPP real,
- autenticación,
- certificado X.509 real con extensiones privadas PQC,
- ML-KEM para acuerdo de clave,
- y métricas medibles.

### Terminal 1

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Terminal 2

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Después del intercambio

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/metrics/analyze_results.py
```

### Qué debes verbalizar durante la ejecución

- El emisor genera el material KEM efímero.
- El HELLO se firma con el esquema PQC seleccionado.
- El receptor valida identidad por certificado y verifica la firma.
- Si la validación es correcta, encapsula el secreto compartido.
- Ambos lados obtienen el mismo secreto y se registran métricas de tiempo y tamaño.

## 6. Resultados concretos que conviene citar

Los siguientes datos salen de artifacts/csv/summary_experiments.csv y artifacts/csv/statistical_analysis.csv.

### Demo 1. Firmas XMPP

- Tiempo medio de firma en emisor: ML-DSA ≈ 0.64 ms frente a SPHINCS ≈ 131.96 ms.
- RTT medio: ML-DSA ≈ 13.08 ms frente a SPHINCS ≈ 59.26 ms.
- Tamaño medio de stanza en emisor: ML-DSA ≈ 7368 bytes frente a SPHINCS ≈ 10889 bytes.
- Tamaño medio de firma en Base64: ML-DSA = 4412 bytes frente a SPHINCS = 10476 bytes.

Interpretación corta:

- SPHINCS introduce una penalización muy fuerte en firma y tamaño.
- ML-DSA resulta mucho más razonable para mensajería interactiva.

### Demo 2A. Handshake híbrido local

- Tiempo medio total emisor: ML-DSA ≈ 0.60 ms frente a SPHINCS ≈ 141.53 ms.
- Tamaño medio de HELLO: ML-DSA ≈ 8748 bytes frente a SPHINCS ≈ 12268 bytes.
- El tamaño de RESPONSE se mantiene prácticamente constante.

Interpretación corta:

- En local se ve muy limpio que el cuello de botella dominante está en la firma del HELLO.

### Demo 2B. Handshake híbrido XMPP

- Tiempo medio de firma del emisor: ML-DSA ≈ 0.56 ms frente a SPHINCS ≈ 161.57 ms.
- RTT medio del handshake: ML-DSA ≈ 73.69 ms frente a SPHINCS ≈ 76.90 ms.
- Tamaño medio de HELLO en emisor: ML-DSA ≈ 16805 bytes frente a SPHINCS ≈ 23879 bytes.
- Tiempo medio de verificación en receptor: ML-DSA ≈ 0.18 ms frente a SPHINCS ≈ 0.82 ms.

Interpretación corta:

- En XMPP la red amortigua parte de la diferencia en RTT total.
- Sin embargo, la diferencia criptográfica y de tamaño sigue siendo contundente.

## 7. Lectura estadística que te conviene decir

No te metas en demasiada teoría. Di algo así:

> Además de medias y medianas, he generado intervalos de confianza al 95% y pruebas Mann-Whitney U para comparar ML-DSA frente a SPHINCS+. En las métricas principales de firma, verificación y tamaño, las diferencias salen claramente significativas.

Eso es suficiente para una demo oral, salvo que el profesor pida más detalle.

## 8. Cómo explicar el tema X.509 sin enredarte

Frase recomendada:

> En la variante con certificados uso un certificado X.509 real, pero el material PQC va en extensiones privadas. Eso me permite mantener una estructura PKI realista aunque la parte PQC completa no esté modelada con OIDs nativos en esta implementación Python.

Si te pregunta por qué no es una PKI PQC totalmente estándar:

- Porque en Python puro con oqs-python no hay una vía madura y estable para emitir y validar certificados PQC completos como sí podría hacerse con OpenSSL y oqs-provider.
- El objetivo aquí es experimental y comparativo, no construir una CA de producción.

## 9. Preguntas que probablemente te hará

### “¿Qué aporta esto frente a una simulación puramente local?”

Respuesta:

- Que aquí se incorpora serialización real en XML/XMPP, transporte real, latencia real y tamaño real de stanzas.
- Eso permite ver el impacto operativo, no solo el coste criptográfico aislado.

### “¿Por qué comparar ML-DSA y SPHINCS+?”

Respuesta:

- Porque representan dos familias PQC con compromisos distintos.
- La comparación enseña muy bien el trade-off entre firma más ligera y firma con mayor coste y tamaño.

### “¿Qué limitaciones tiene tu implementación?”

Respuesta:

- Entorno de laboratorio sin TLS en la parte XMPP.
- Parte de identidad todavía experimental y simplificada.
- No hay todavía baseline clásico frente a RSA/ECDSA o Kyber+Ed25519 equivalente.
- El servidor XMPP y la máquina anfitriona pueden introducir ruido temporal en las mediciones.

### “¿Cuál es tu conclusión práctica?”

Respuesta:

- Que la integración es viable, pero la elección del esquema de firma es crítica.
- ML-DSA parece mucho más adecuado que SPHINCS+ para escenarios interactivos sobre mensajería.

## 10. Mejoras concretas que puedes proponer tú mismo

Conviene anticiparte y cerrar con criterio técnico. Estas mejoras son defendibles:

1. Añadir comparación con criptografía clásica para disponer de una referencia base.
2. Persistir identidades y certificados entre ejecuciones para aproximar un sistema real.
3. Desplegar el stack con TLS y una infraestructura XMPP más cercana a producción.
4. Integrar análisis de consumo de CPU y memoria además de latencia y tamaño.
5. Usar OpenSSL + oqs-provider para una historia X.509/PKI más estándar.
6. Separar mejor el coste de serialización, red y criptografía en el análisis.

## 11. Plan de demo mínimo si el tiempo aprieta

Si solo tienes 5 a 7 minutos, haz esto:

1. Explica la motivación en 30 segundos.
2. Enseña el esquema de demos en el README.
3. Ejecuta Demo 2B modo cert.
4. Muestra summary_experiments.csv.
5. Cierra con la conclusión principal: ML-DSA rinde mucho mejor que SPHINCS+ en este contexto.

## 12. Plan de contingencia si algo falla en directo

Si el servidor XMPP no responde o la red falla:

1. Enseña scripts/run_all_demos.sh y explica el flujo automatizado.
2. Muestra artifacts/logs/run_all para evidenciar ejecuciones previas reales.
3. Enseña los CSV ya generados.
4. Enseña los PCAP en artifacts/pcap y abre uno en Wireshark si quieres reforzar que hubo intercambio real.
5. Ejecuta al menos Demo 2A local y el análisis estadístico, que no dependen de XMPP.

## 13. Frase final recomendada

Puedes cerrar así:

> El trabajo ya demuestra viabilidad técnica, medición reproducible y capacidad de comparación. El siguiente salto no es hacer que funcione por primera vez, sino endurecer el modelo de confianza, mejorar la reproducibilidad y acercarlo a un escenario más realista de despliegue.
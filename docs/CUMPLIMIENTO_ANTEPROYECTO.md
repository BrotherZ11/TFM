# Matriz de cumplimiento del anteproyecto

Este documento verifica, punto por punto, que el repositorio implementa lo comprometido en el anteproyecto del TFM.

## 1) Contextualización y motivación

El proyecto implementa un entorno experimental XMPP + PQC centrado en:
- Riesgo post-cuántico sobre autenticidad/confidencialidad.
- Integración práctica de ML-KEM + ML-DSA/SPHINCS+.
- Cuantificación de overhead, latencia y coste criptográfico.

Evidencia en el repositorio:
- Diseño formal del protocolo híbrido: `docs/FASE1_diseno_protocolo_hibrido.md`.
- Implementación de handshake y firmas en XMPP: `src/demoB/*.py`, `src/demoA/*.py`.

## 2) Objetivos del TFM

### Objetivo 1 — Firmas post-cuánticas en stanzas XML
✅ Cumplido.
- Firma/verificación PQ en mensajes XMPP (Demo A y Demo B).
- Algoritmos comparables: ML-DSA y SPHINCS+.

Evidencia:
- `src/demoA/emisor.py`, `src/demoA/receptor.py`.
- `src/protocol/hybrid_protocol.py` (firma canónica).

### Objetivo 2 — Handshake híbrido con ML-KEM autenticado
✅ Cumplido.
- Flujo `pq:init -> pq:reply -> pq:final`.
- Encapsulado/decapsulado ML-KEM + autenticación por firma PQ.

Evidencia:
- `src/demoB/emisor_hybrid.py`, `src/demoB/receptor_hybrid.py`.
- `src/protocol/hybrid_protocol.py`.

### Objetivo 3 — Monitorización en tiempo real
✅ Cumplido.
- Métricas de firmado, verificación, RTT, tamaño de stanza.
- Exportación CSV y estadísticas en vivo.

Evidencia:
- `src/demoA/emisor_bench.py`, `src/demoA/receptor_bench.py`.
- `src/metrics/realtime.py`.
- CSVs en `artifacts/csv/`.

### Objetivo 4 — Análisis experimental y comparativo
✅ Cumplido.
- Plan reproducible de experimentos con semilla.
- Orquestación por lotes.
- Resumen estadístico por algoritmo y métrica.

Evidencia:
- `src/metrics/experiment_plan.py`.
- `src/metrics/run_experiment.py`.
- `src/metrics/analyze_phase4.py`.
- `src/metrics/plot_metrics.py`.

## 3) Entregables comprometidos

### Código fuente
✅ Cumplido (`src/`, `docs/`, `tests/`).

### Gráficas y visualizaciones comparativas
✅ Cumplido.
- Generación mediante `src/metrics/plot_metrics.py`.
- Ejemplos existentes en `artifacts/figs/`.

### Capturas de tráfico PCAP/PCAPNG
✅ Cumplido.
- Muestras en `artifacts/pcap/`.

### Documento final del TFM
🟡 Parcial en este repositorio.
- El repositorio aporta insumos técnicos y resultados.
- La memoria final se redacta fuera del código fuente.

## 4) Metodología incremental e iterativa

✅ Cumplido.
- Diseño por fases (`docs/FASE1..FASE5`).
- Implementación modular (protocolo / demos / métricas / análisis).
- Validación incremental con tests.

## 5) Fases de trabajo declaradas

1. Investigación/estado del arte → ✅ reflejado en documentación de diseño.
2. Diseño del sistema → ✅ Fase 1.
3. Implementación PQC → ✅ Demo A + utilidades protocolo.
4. Handshake post-cuántico → ✅ Demo B.
5. Monitorización y captura de métricas → ✅ Bench + métricas + CSV.
6. Experimentación y validación → ✅ plan + runbook + ejecución.
7. Análisis de resultados → ✅ resumen estadístico + plots.
8. Documentación final → ✅ documentación técnica de fases; memoria final externa.

## 6) Entorno tecnológico comprometido

✅ Cumplido:
- Python.
- XMPP (Slixmpp).
- Open Quantum Safe/liboqs (vía oqs-python).
- Wireshark (capturas `pcap/pcapng`).
- Matplotlib (gráficas).

## 7) Observaciones de calidad técnica

- Se ha priorizado entorno de laboratorio y reproducibilidad.
- No se amplía alcance a PKI/federación real (alineado con anteproyecto).
- Se incluyen checks automatizados para evitar regresiones.

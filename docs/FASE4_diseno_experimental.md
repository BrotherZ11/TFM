# FASE 4 — Diseño experimental comparativo (implementado)

## Objetivo
Comparar ML-DSA vs SPHINCS+ bajo misma infraestructura XMPP y mismo KEM.

## Diseño recomendado
- Algoritmos de firma:
  - `ML-DSA-65`
  - `SPHINCS+-SHA2-128s-simple`
- KEM fijo:
  - `ML-KEM-768`
- Réplicas mínimas defendibles:
  - 30 handshakes por algoritmo (60 total)
- Orden de ejecución:
  - Aleatorio, con semilla fija para reproducibilidad.

## Estadística aplicada
- Para cada métrica:
  - `n`, media, mediana, desviación típica, `p95`, `ci95_half_width`.
- Comparativa por algoritmo a partir de resumen CSV generado por script.

## Scripts
- Plan:
  - `PYTHONPATH=src python src/metrics/experiment_plan.py --repetitions 30 --seed 42`
- Ejecución:
  - `PYTHONPATH=src python src/metrics/run_experiment.py --plan artifacts/csv/experiment_plan.csv`
- Resumen:
  - `PYTHONPATH=src python src/metrics/analyze_phase4.py`

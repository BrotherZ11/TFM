# FASE 3 — Sistema de métricas (implementado)

## Objetivo
Separar coste criptográfico y coste de red, almacenar resultados reproducibles y habilitar repetición experimental.

## Qué se mide
- Coste criptográfico (local):
  - Firma (`sign_*_ms`)
  - Verificación (`verify_*_ms`)
  - Encapsulado/decapsulado (`kem_encap_ms`, `decap_ms`)
- Coste de red:
  - `rtt_ms`
- Overhead:
  - `stanza_init_bytes`
  - `stanza_reply_bytes`

## Almacenamiento
- `artifacts/csv/handshake_sender.csv`
- `artifacts/csv/handshake_receiver.csv`
- Resumen automático:
  - `artifacts/csv/phase4_summary.csv`
  - `artifacts/reports/phase4_summary.md`

## Repetibilidad
- Plan experimental reproducible con semilla:
  - `src/metrics/experiment_plan.py`
- Ejecución por lotes:
  - `src/metrics/run_experiment.py`

## Criterio de cierre
Existe pipeline reproducible que genere plan, capture métricas y produzca resumen estadístico.

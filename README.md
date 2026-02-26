# TFM

Documentación de trabajo:

- [FASE 1 — Diseño formal del protocolo híbrido](docs/FASE1_diseno_protocolo_hibrido.md)
- [FASE 2 — Integración con Slixmpp](docs/FASE2_integracion_slixmpp.md)
- [FASE 3 — Sistema de métricas](docs/FASE3_sistema_metricas.md)
- [FASE 4 — Diseño experimental comparativo](docs/FASE4_diseno_experimental.md)
- [FASE 5 — Análisis final](docs/FASE5_analisis_final.md)

## Implementación

### Núcleo de protocolo
- `src/protocol/hybrid_protocol.py`
  - JSON canónico para firma/validación.
  - Wrappers ML-KEM y firmas PQ.
  - Derivación de clave de sesión.
  - Validación de campos requeridos.

### Handshake híbrido XMPP
- `src/demoB/receptor_hybrid.py`
- `src/demoB/emisor_hybrid.py`
- `src/demoB/setup_keys.py`
- `src/demoB/keyring.py`

### Métricas y análisis
- `src/metrics/experiment_plan.py` (plan reproducible)
- `src/metrics/run_experiment.py` (runbook/ejecución)
- `src/metrics/analyze_phase4.py` (resumen estadístico + reporte)

## Flujo completo (todas las fases)

1. Generar claves:

```bash
PYTHONPATH=src python src/demoB/setup_keys.py --sig ML-DSA-65 --kem ML-KEM-768
```

2. Ejecutar handshake manual (una corrida):

```bash
PYTHONPATH=src python src/demoB/receptor_hybrid.py --host 10.255.255.254 --port 5222 --run-id manual_001
PYTHONPATH=src python src/demoB/emisor_hybrid.py --host 10.255.255.254 --port 5222 --run-id manual_001 --timeout 5.0
```

3. Generar plan experimental (FASE 4):

```bash
PYTHONPATH=src python src/metrics/experiment_plan.py --repetitions 30 --seed 42
```

4. Revisar runbook de ejecución:

```bash
PYTHONPATH=src python src/metrics/run_experiment.py --plan artifacts/csv/experiment_plan.csv
```

5. Ejecutar runbook automáticamente (opcional):

```bash
PYTHONPATH=src python src/metrics/run_experiment.py --plan artifacts/csv/experiment_plan.csv --execute --startup-delay 1.0 --timeout 5.0
```

6. Generar resumen estadístico (FASE 5):

```bash
PYTHONPATH=src python src/metrics/analyze_phase4.py
```

7. Validar cumplimiento estructural del anteproyecto:

```bash
PYTHONPATH=src python src/metrics/validate_anteproyecto.py
```

## Artefactos
- CSV handshake:
  - `artifacts/csv/handshake_sender.csv`
  - `artifacts/csv/handshake_receiver.csv`
- Plan:
  - `artifacts/csv/experiment_plan.csv`
- Resumen y reporte:
  - `artifacts/csv/phase4_summary.csv`
  - `artifacts/csv/phase4_mannwhitney.csv`
  - `artifacts/reports/phase4_summary.md`
  - `artifacts/figs/phase4/*.png`

## Tests

```bash
python -m py_compile src/protocol/hybrid_protocol.py src/demoB/keyring.py src/demoB/setup_keys.py src/demoB/receptor_hybrid.py src/demoB/emisor_hybrid.py src/metrics/experiment_plan.py src/metrics/run_experiment.py src/metrics/analyze_phase4.py src/metrics/validate_anteproyecto.py tests/test_protocol_utils.py tests/test_metrics_phase4.py tests/test_validate_anteproyecto.py
PYTHONPATH=src python -m unittest discover -s tests -p 'test_*.py'
```

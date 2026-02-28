# Demo 3 — Análisis experimental

Objetivo: analizar y comparar resultados (latencia, tamaños y tiempos) entre esquemas de firma y handshake híbrido.

## Scripts
- `src/metrics/plot_metrics.py` (gráficas de firmas XMPP)
- `src/metrics/plot_kem_signed_metrics.py` (gráficas handshake híbrido local)
- `src/metrics/plot_hybrid_xmpp_metrics.py` (gráficas handshake híbrido XMPP)
- `src/metrics/summarize_experiments.py` (resumen global media/mediana/p95)

## Ejecución

```bash
PYTHONPATH=src venv/bin/python src/metrics/plot_metrics.py
PYTHONPATH=src venv/bin/python src/metrics/plot_kem_signed_metrics.py
PYTHONPATH=src venv/bin/python src/metrics/plot_hybrid_xmpp_metrics.py
PYTHONPATH=src venv/bin/python src/metrics/summarize_experiments.py
```

Resultados:
- gráficas en `artifacts/figs/`
- resumen tabular en `artifacts/csv/summary_experiments.csv`

## Captura de tráfico
Para análisis con Wireshark usa los PCAP en:
- `artifacts/pcap/`

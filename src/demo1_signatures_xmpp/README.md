# Demo 1 — Firmas PQC en XMPP

Objetivo: firmar y verificar mensajes XMPP con `ML-DSA` y `SPHINCS+`, embebiendo firma y clave pública en la stanza XML.

## Scripts
- `src/demoA/emisor.py`
- `src/demoA/receptor.py`
- `src/demoA/emisor_bench.py`
- `src/demoA/receptor_bench.py`

## Ejecución rápida
1. Lanza el receptor benchmark:
   - `PYTHONPATH=src venv/bin/python src/demoA/receptor_bench.py`
2. Lanza el emisor benchmark:
   - `PYTHONPATH=src venv/bin/python src/demoA/emisor_bench.py`

Los CSV se guardan en:
- `artifacts/csv/sender_metrics.csv`
- `artifacts/csv/receiver_metrics.csv`

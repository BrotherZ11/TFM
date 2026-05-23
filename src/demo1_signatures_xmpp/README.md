# Demo 1 — Firmas PQC en XMPP

Objetivo: firmar y verificar mensajes XMPP con `ML-DSA` y `SPHINCS+`, embebiendo firma y clave pública en la stanza XML.

## Scripts
- `src/demo1_signatures_xmpp/emisor.py`
- `src/demo1_signatures_xmpp/receptor.py`
- `src/demo1_signatures_xmpp/emisor_bench.py`
- `src/demo1_signatures_xmpp/receptor_bench.py`

## Ejecución rápida
1. Lanza el receptor benchmark:
   - `PYTHONPATH=src venv/bin/python src/demo1_signatures_xmpp/receptor_bench.py`
2. Lanza el emisor benchmark:
   - `PYTHONPATH=src venv/bin/python src/demo1_signatures_xmpp/emisor_bench.py`

Los CSV se guardan en:
- `artifacts/csv/sender_metrics.csv`
- `artifacts/csv/receiver_metrics.csv`

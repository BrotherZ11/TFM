# TFM — XMPP + Criptografía Post-Cuántica

Este repositorio implementa y evalúa experimentalmente mensajería XMPP con PQC, cubriendo:

1. Firma/verificación en stanzas XMPP con `ML-DSA` y `SPHINCS+`.
2. Handshake híbrido con `ML-KEM-768` autenticado por firma PQC.
3. Captura de métricas de rendimiento, tamaño y latencia.
4. Análisis comparativo y visualización de resultados.

## Estructura por demos

- `src/demo1_signatures_xmpp/`: demo y benchmark de firmas PQC en XMPP.
- `src/demo2_hybrid_kem_signed/`: benchmark de handshake híbrido (`ML-KEM` + firma).
- `src/demo3_analysis/`: guía de análisis y comparación.

Implementación principal reutilizable:
- `src/crypto/pqc_wrapper.py`
- `src/demoA/emisor.py`
- `src/demoA/receptor.py`
- `src/demoA/emisor_bench.py`
- `src/demoA/receptor_bench.py`
- `src/demoA/kem_signed_bench.py`
- `src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py`
- `src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py`
- `src/demo2_hybrid_kem_signed/pqc_pki_tool.py`
- `src/demo2_hybrid_kem_signed/x509_pqc_notes.md`
- `src/metrics/plot_metrics.py`
- `src/metrics/plot_kem_signed_metrics.py`
- `src/metrics/plot_hybrid_xmpp_metrics.py`
- `src/metrics/summarize_experiments.py`

## Requisitos

- Python 3.10+
- Dependencias en `requirements.txt`

Instalación:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Demo 1: firmas PQC en XMPP

Receptor:

```bash
PYTHONPATH=src venv/bin/python src/demoA/receptor_bench.py
```

Emisor:

```bash
PYTHONPATH=src venv/bin/python src/demoA/emisor_bench.py
```

Salida:
- `artifacts/csv/sender_metrics.csv`
- `artifacts/csv/receiver_metrics.csv`

## Demo 2: handshake híbrido firmado (ML-KEM + ML-DSA/SPHINCS)

```bash
PYTHONPATH=src venv/bin/python src/demoA/kem_signed_bench.py --iterations 20
```

Salida:
- `artifacts/csv/kem_signed_sender_metrics.csv`
- `artifacts/csv/kem_signed_receiver_metrics.csv`

## Demo 2B: handshake híbrido real sobre XMPP

Receptor:

```bash
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py
```

Emisor:

```bash
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py
```

Salida:
- `artifacts/csv/hybrid_xmpp_sender_metrics.csv`
- `artifacts/csv/hybrid_xmpp_receiver_metrics.csv`

Modos de verificación soportados:
- `cert`: certificado PQC (perfil X.509-like) firmado con ML-DSA/SPHINCS+
- `qr`: pinning por huella (simulación de validación por QR)

## Demo 3: análisis y gráficas

Firmas XMPP:

```bash
PYTHONPATH=src venv/bin/python src/metrics/plot_metrics.py
```

Handshake híbrido:

```bash
PYTHONPATH=src venv/bin/python src/metrics/plot_kem_signed_metrics.py
```

Handshake híbrido XMPP:

```bash
PYTHONPATH=src venv/bin/python src/metrics/plot_hybrid_xmpp_metrics.py
```

Resumen estadístico global (media/mediana/p95):

```bash
PYTHONPATH=src venv/bin/python src/metrics/summarize_experiments.py
```

Figuras en:
- `artifacts/figs/`

## Captura de red (Wireshark / tshark)

Los PCAP de ejemplo están en `artifacts/pcap/` y se pueden analizar con Wireshark para estudiar tamaño real de stanzas y patrón de intercambio.

Captura reproducible con `tshark` (si está instalado):

```bash
mkdir -p artifacts/pcap
sudo tshark -i any -f "tcp port 5222" -w artifacts/pcap/hybrid_xmpp_capture.pcapng
```

Durante la captura, ejecutar `receptor_hybrid_bench.py` y `emisor_hybrid_bench.py`, luego detener captura y abrir el `.pcapng` en Wireshark.

## Ejecución automática completa (script único)

Puedes ejecutar todas las demos + análisis con un solo comando:

```bash
./scripts/run_all_demos.sh
```

Opciones rápidas por variables de entorno:

- Reducir iteraciones del benchmark local:

```bash
LOCAL_ITERS=10 ./scripts/run_all_demos.sh
```

- Saltar el modo QR:

```bash
RUN_QR=0 ./scripts/run_all_demos.sh
```

- Cambiar endpoint XMPP (por defecto usa `127.0.0.1:5222`):

```bash
XMPP_HOST=127.0.0.1 XMPP_PORT=5222 ./scripts/run_all_demos.sh
```

- Ajustar timeout por fase (evita bloqueos indefinidos):

```bash
TIMEOUT_DEMO1=300 TIMEOUT_DEMO2B=360 ./scripts/run_all_demos.sh
```

Logs detallados por fase en:

- `artifacts/logs/run_all/<timestamp>/`
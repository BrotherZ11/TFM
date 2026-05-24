# TFM — XMPP + Criptografía Post-Cuántica

Implementación experimental y evaluación de mensajería XMPP con criptografía post-cuántica (PQC), desarrollado como Trabajo de Fin de Máster en la Universidad de Málaga.

Cubre:

1. Firma/verificación de stanzas XMPP con `ML-DSA-65` y `SPHINCS+-SHA2-128s`.
2. Handshake híbrido KEM+firma con `ML-KEM-768` autenticado por firma PQC.
3. Captura de métricas de rendimiento, tamaño, latencia y uso de CPU/memoria.
4. Dashboard interactivo Streamlit para demo en vivo ante el tribunal.

## Estructura del proyecto

```
src/
  crypto/
    pqc_wrapper.py          — Capa criptográfica PQC reutilizable (liboqs)
    pqc_certificate.py      — Utilidades X.509 con extensiones PQC
  demo1_signatures_xmpp/
    emisor.py               — Emisor XMPP con firma PQC (modo interactivo)
    emisor_bench.py         — Emisor benchmark: firma + métricas CPU/mem
    receptor.py             — Receptor XMPP con verificación PQC
    receptor_bench.py       — Receptor benchmark
  demo2_hybrid_kem_signed/
    kem_signed_bench.py     — Handshake híbrido local (sin XMPP), benchmark
    emisor_hybrid_bench.py  — Emisor handshake híbrido sobre XMPP, benchmark
    receptor_hybrid_bench.py— Receptor handshake híbrido sobre XMPP
    protocol.py             — Lógica del protocolo HELLO firmado + KEM
    pqc_pki_tool.py         — Herramienta de PKI PQC (generación de certificados)
    x509_pqc_notes.md       — Notas sobre X.509 con extensiones PQC
  demo3_analysis/
    analyze_pcap.py         — Análisis de capturas PCAP con scapy
  demo_live/
    app.py                  — Dashboard Streamlit para la defensa (3 pestañas)
  metrics/
    analyze_results.py      — Análisis estadístico de CSVs (Mann-Whitney, IC 95%)
    crypto_comparison_bench.py — Benchmark clásico (RSA/ECDSA/ECDH) vs PQC
    plot_comparison.py      — Figuras comparativas clásico vs PQC
    plot_metrics.py         — Gráficas de Demo 1 (firmas XMPP)
    plot_kem_signed_metrics.py  — Gráficas de Demo 2A (handshake local)
    plot_hybrid_xmpp_metrics.py — Gráficas de Demo 2B (handshake XMPP)
    realtime.py             — Monitor de métricas en tiempo real
    summarize_experiments.py— Resumen estadístico global (media/mediana/p95)
artifacts/
  csv/                      — CSVs generados por los benchmarks
  figs/                     — Figuras PNG generadas por los scripts de métricas
  pcap/                     — Capturas de red .pcapng
  logs/                     — Logs de ejecuciones anteriores
scripts/
  run_all_demos.sh          — Automatización completa de todas las demos
report/
  checklist_demo.md         — Checklist rápido para la defensa
  demo_profesor.md          — Guion de exposición para el tribunal
  demo_funcionamiento_profesor.md — Detalle funcional de la demo
  ejecucion_demos_wsl_tshark.md   — Guía ejecución en WSL + captura tshark
```

## Requisitos

- Python 3.10+ (probado con 3.12 en WSL2 Ubuntu 24.04, x86-64)
- Servidor XMPP Prosody en `127.0.0.1:5222` (sin TLS) para demos 1 y 2B
- Dependencias en `requirements.txt`:
  - `liboqs-python` (liboqs 0.14.1+) — ML-DSA, SPHINCS+, ML-KEM
  - `slixmpp` — cliente XMPP asíncrono
  - `streamlit` — dashboard de demo en vivo
  - `qrcode[pil]` — generación de QR para el chat del jurado
  - `psutil` — métricas de CPU y memoria durante benchmarks
  - `pandas`, `scipy`, `matplotlib` — análisis y visualización

Instalación:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Demo en vivo — Dashboard Streamlit (recomendado para la defensa)

Arranca el dashboard interactivo con 3 pestañas:

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src streamlit run src/demo_live/app.py --server.address 0.0.0.0
```

Abre `http://localhost:8501` en el navegador.

**Pestañas disponibles:**

| Pestaña | Descripción |
|---------|-------------|
| ✍️ Firma PQC en directo | Firma y verifica cualquier mensaje con ML-DSA-65 o SPHINCS+; compara ambos en una tabla |
| 🤝 Handshake Híbrido | Ejecuta el protocolo KEM+firma paso a paso con animación y métricas |
| 💬 Chat en Vivo | El jurado escanea un QR con el móvil, envía mensajes firmados con PQC y el presentador los ve llegar verificados en tiempo real |

**Vista del jurado** (`?role=jury`): al escanear el QR, el miembro del tribunal accede a un formulario móvil donde escribe su mensaje, elige el algoritmo PQC y lo envía firmado. Las métricas de firma llegan inmediatamente a la pantalla del presentador.

---

## Demo 1: firmas PQC en XMPP

Requiere servidor XMPP en `127.0.0.1:5222`.

Terminal 1 — Receptor:

```bash
PYTHONPATH=src venv/bin/python src/demo1_signatures_xmpp/receptor_bench.py \
  --host 127.0.0.1 --port 5222 --startup-timeout 20
```

Terminal 2 — Emisor:

```bash
PYTHONPATH=src venv/bin/python src/demo1_signatures_xmpp/emisor_bench.py \
  --host 127.0.0.1 --port 5222 --startup-timeout 20
```

Salida: `artifacts/csv/sender_metrics.csv`, `artifacts/csv/receiver_metrics.csv`

---

## Demo 2A: handshake híbrido local (sin red)

```bash
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/kem_signed_bench.py --iterations 20
```

Salida: `artifacts/csv/kem_signed_sender_metrics.csv`, `artifacts/csv/kem_signed_receiver_metrics.csv`

---

## Demo 2B: handshake híbrido sobre XMPP

Requiere servidor XMPP en `127.0.0.1:5222`.

Terminal 1 — Receptor:

```bash
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py \
  --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

Terminal 2 — Emisor:

```bash
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py \
  --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

Salida: `artifacts/csv/hybrid_xmpp_sender_metrics.csv`, `artifacts/csv/hybrid_xmpp_receiver_metrics.csv`

Modos de verificación (`--verify-mode`):
- `cert` — certificado X.509 con extensiones PQC (modo recomendado)
- `qr` — pinning por huella SHA-256 (simulación de validación por QR)

---

## Métricas y análisis

Gráficas de Demo 1 (firmas XMPP):

```bash
PYTHONPATH=src venv/bin/python src/metrics/plot_metrics.py
```

Gráficas de Demo 2A (handshake local):

```bash
PYTHONPATH=src venv/bin/python src/metrics/plot_kem_signed_metrics.py
```

Gráficas de Demo 2B (handshake XMPP):

```bash
PYTHONPATH=src venv/bin/python src/metrics/plot_hybrid_xmpp_metrics.py
```

Comparativa clásico (RSA/ECDSA/ECDH) vs PQC:

```bash
PYTHONPATH=src venv/bin/python src/metrics/crypto_comparison_bench.py --iterations 50
PYTHONPATH=src venv/bin/python src/metrics/plot_comparison.py
```

Análisis estadístico completo (Mann-Whitney U, IC 95%, p-valor):

```bash
PYTHONPATH=src venv/bin/python src/metrics/analyze_results.py
```

Resumen global por experimento (media/mediana/p95):

```bash
PYTHONPATH=src venv/bin/python src/metrics/summarize_experiments.py
```

---

## Automatización completa

```bash
./scripts/run_all_demos.sh
```

Ejecuta todas las demos en secuencia y regenera CSVs, gráficas y resumen estadístico.

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
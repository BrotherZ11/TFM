# Guía de ejecución de demos en WSL Ubuntu + captura con tshark

## 0) Preparación (una sola vez)

Desde WSL Ubuntu, en la raíz del proyecto:

```bash
cd /home/david/TFM
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Instalar `tshark` (si no está instalado):

```bash
sudo apt update
sudo apt install -y tshark
```

---

## Dashboard Streamlit — Demo en vivo para la defensa

No requiere servidor XMPP. Una sola terminal:

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src streamlit run src/demo_live/app.py --server.address 0.0.0.0
```

Abre `http://localhost:8501` en el navegador.

Para que el tribunal acceda al chat QR desde su móvil (misma red WiFi):
- La IP del portátil se detecta automáticamente.
- En WSL2, puede ser necesario reenviar el puerto desde Windows:
  ```powershell
  netsh interface portproxy add v4tov4 listenport=8501 listenaddress=0.0.0.0 connectport=8501 connectaddress=<IP-WSL>
  ```

---

Crear carpeta de capturas:

```bash
mkdir -p artifacts/pcap
```

> Nota: en demos XMPP se asume servidor en `127.0.0.1:5222`.

---

## 1) Demo 1 — Firmas PQC en XMPP

### Terminal A — Captura tshark

```bash
cd /home/david/TFM
sudo tshark -i any -f "tcp port 5222" -w artifacts/pcap/demo1_signatures_xmpp.pcapng
```

### Terminal B — Receptor

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo1_signatures_xmpp/receptor_bench.py --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Terminal C — Emisor

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo1_signatures_xmpp/emisor_bench.py --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Parar captura

En Terminal A: `Ctrl+C`

---

## 2) Demo 2A — Handshake híbrido local (sin red)

Este benchmark es local (sin XMPP), por lo que no hay tráfico de aplicación en red que capturar.

### Ejecución

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/kem_signed_bench.py --iterations 20
```

### Captura tshark (opcional, esperable casi vacía)

```bash
cd /home/david/TFM
sudo tshark -i any -a duration:60 -w artifacts/pcap/demo2a_local_optional.pcapng
```

---

## 3) Demo 2B — Handshake híbrido XMPP (modo cert, X.509 real)

### Terminal A — Captura tshark

```bash
cd /home/david/TFM
sudo tshark -i any -f "tcp port 5222" -w artifacts/pcap/demo2b_hybrid_xmpp_cert.pcapng
```

### Terminal B — Receptor (cert)

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Terminal C — Emisor (cert)

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Parar captura

En Terminal A: `Ctrl+C`

### Comparativa nueva (SPHINCS+ vs ML-DSA)

Tras ejecutar Demo 2B, genera el análisis estadístico (IC95 + Mann-Whitney U):

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/metrics/analyze_results.py
```

Resultado:
- `artifacts/csv/statistical_analysis.csv`

---

## 4) Demo 2C — Handshake híbrido XMPP (modo qr)

### Terminal A — Captura tshark

```bash
cd /home/david/TFM
sudo tshark -i any -f "tcp port 5222" -w artifacts/pcap/demo2c_hybrid_xmpp_qr.pcapng
```

### Terminal B — Receptor (qr)

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py --verify-mode qr --trusted-fingerprints-file artifacts/csv/trusted_qr_fingerprints.txt --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Terminal C — Emisor (qr)

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py --verify-mode qr --qr-fingerprint-output-file artifacts/csv/trusted_qr_fingerprints.txt --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Parar captura

En Terminal A: `Ctrl+C`

---

## 5) Demo 3 — Análisis y generación de gráficas

No requiere tráfico de red: procesa CSV ya generados.

### Ejecución

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/metrics/plot_metrics.py
PYTHONPATH=src venv/bin/python src/metrics/plot_kem_signed_metrics.py
PYTHONPATH=src venv/bin/python src/metrics/plot_hybrid_xmpp_metrics.py
PYTHONPATH=src venv/bin/python src/metrics/summarize_experiments.py
PYTHONPATH=src venv/bin/python src/metrics/analyze_results.py
```

### Captura tshark (opcional, esperable vacía)

```bash
cd /home/david/TFM
sudo tshark -i any -a duration:30 -w artifacts/pcap/demo3_analysis_optional.pcapng
```

---

## 6) Ejecución completa automática (opcional)

```bash
cd /home/david/TFM
./scripts/run_all_demos.sh
```

Con captura global durante toda la ejecución:

```bash
cd /home/david/TFM
sudo tshark -i any -f "tcp port 5222" -w artifacts/pcap/run_all_demos.pcapng
```

En otra terminal:

```bash
cd /home/david/TFM
./scripts/run_all_demos.sh
```

Al terminar, ejecuta también el análisis estadístico nuevo:

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/metrics/analyze_results.py
```

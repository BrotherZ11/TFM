# Checklist rápido para la demo

1. Arranca o verifica el servidor XMPP en 127.0.0.1:5222.
2. Comprueba que el entorno virtual existe en venv.
3. Abre tres terminales situadas en /home/david/TFM.
4. Ten abierto el README y el fichero report/demo_funcionamiento.md.
5. Deja preparada la carpeta artifacts/figs para enseñar una gráfica sin buscarla en directo.

## Comprobación rápida de entorno

```bash
cd /home/david/TFM
source venv/bin/activate
/home/david/TFM/venv/bin/python --version
```

## Demo recomendada

La más equilibrada para enseñar valor técnico es Demo 2B en modo cert.

Guion reducido centrado en funcionamiento e implementación:

- report/demo_funcionamiento.md

### Terminal 1: receptor

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Terminal 2: emisor

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Terminal 3: análisis posterior

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/metrics/analyze_results.py
```

## Si quieres ir a lo seguro

Ejecuta primero el flujo completo antes de la reunión para regenerar logs y confirmar que todo responde:

```bash
cd /home/david/TFM
./scripts/run_all_demos.sh
```

## Archivos que debes tener a mano para enseñar

1. README.md
2. scripts/run_all_demos.sh
3. src/crypto/pqc_wrapper.py
4. src/demo2_hybrid_kem_signed/protocol.py
5. artifacts/csv/summary_experiments.csv
6. artifacts/csv/statistical_analysis.csv
7. artifacts/figs/hybrid_xmpp_box_sign_ms.png
8. artifacts/figs/hybrid_xmpp_box_rtt_ms.png

## Mensajes clave para decir en voz alta

1. He integrado firmas PQC y handshake híbrido en un flujo XMPP realista.
2. No solo funciona: también he medido latencia, tiempo criptográfico y tamaño de mensajes.
3. ML-DSA sale claramente mejor parado que SPHINCS+ en este contexto.
4. La siguiente mejora natural es endurecer identidad, PKI y reproducibilidad experimental.

## Si falla XMPP

1. No pierdas tiempo depurando en directo.
2. Enseña ejecuciones previas en artifacts/logs/run_all.
3. Enseña CSV y gráficas ya generados.
4. Ejecuta Demo 2A local como respaldo.

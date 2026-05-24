# Checklist rápido para la defensa

## Antes de empezar

1. Arranca o verifica el servidor XMPP en `127.0.0.1:5222` (necesario solo si haces demos 1 o 2B).
2. Comprueba que el entorno virtual existe en `venv/`.
3. Ten el navegador listo para abrir `http://localhost:8501`.
4. Si el jurado usa el chat QR: asegúrate de que el portátil está en la misma red WiFi que los móviles del tribunal.

## Comprobación rápida de entorno

```bash
cd /home/david/TFM
source venv/bin/activate
venv/bin/python --version   # debe mostrar Python 3.12.x
python -c "import oqs; print('oqs OK')"
python -c "import streamlit; print('streamlit', streamlit.__version__)"
```

---

## Demo principal: Dashboard Streamlit (recomendada)

Una sola terminal:

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src streamlit run src/demo_live/app.py --server.address 0.0.0.0
```

Abre `http://localhost:8501` y navega por las 3 pestañas.

### Orden sugerido durante la exposición

1. **Pestaña ✍️ Firma PQC en directo** — escribe cualquier frase, pulsa Firmar, muestra los tiempos. Después pulsa “Comparar los dos algoritmos” y comenta la tabla.
2. **Pestaña ✍️ → botón Comparar** — ML-DSA-65 vs SPHINCS+, comenta la diferencia x400 en tiempo de firma.
3. **Pestaña 🤝 Handshake Híbrido** — selecciona algoritmo, pulsa Iniciar, muestra los 7 pasos animados.
4. **Pestaña 💬 Chat en Vivo** — pide a alguien del tribunal que escanee el QR, enviar un mensaje, que llegue firmado en pantalla.

---

## Demo alternativa por terminal (si el dashboard falla)

### Terminal 1: receptor

```bash
cd /home/david/TFM && source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py \
  --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Terminal 2: emisor

```bash
cd /home/david/TFM && source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py \
  --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

---

## Archivos clave para enseñar

1. `README.md` — estructura general del proyecto
2. `src/crypto/pqc_wrapper.py` — capa criptográfica reutilizable
3. `src/demo2_hybrid_kem_signed/protocol.py` — mensaje HELLO firmado
4. `src/demo_live/app.py` — dashboard en vivo
5. `scripts/run_all_demos.sh` — automatización completa

## Mensajes clave para decir en voz alta

1. He integrado firmas PQC y handshake híbrido en un flujo XMPP realista.
2. No solo funciona: mido latencia, coste criptográfico, tamaño de mensajes y uso de CPU.
3. ML-DSA sale mejor parado que SPHINCS+ en tiempo y tamaño.
4. El dashboard permite que el propio jurado participe en la demo en tiempo real.

## Si falla XMPP

1. El dashboard funciona completamente sin XMPP (pestañas 1 y 2 son locales).
2. El chat del jurado (pestaña 3) tampoco requiere XMPP.
3. Si falla el dashboard, ejecuta Demo 2A local como respaldo (no necesita XMPP).

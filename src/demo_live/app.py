"""
Demo en vivo — Dashboard PQC+XMPP para la defensa del TFM

Uso (desde la raíz del proyecto):
    streamlit run src/demo_live/app.py --server.address 0.0.0.0

Pestañas (vista presentador):
  1. ✍️  Firma PQC en directo    — keygen + sign + verify sobre texto libre; comparativa ML-DSA-65 vs SPHINCS+
  2. 🤝  Handshake Híbrido       — protocolo KEM + firma animado paso a paso con métricas reales
  3. 💬  Chat en Vivo            — el jurado escanea un QR y envía mensajes firmados con PQC en tiempo real

Vista jurado (?role=jury):
  Formulario móvil-friendly accesible vía QR. El mensaje se firma con el
  algoritmo elegido y llega a la pestaña del presentador con auto-refresco cada 3 s.
"""

import sys
import json
import hashlib
import base64
import time
import os
import io
import socket
import subprocess
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import qrcode
import streamlit as st
import pandas as pd

# ── rutas del proyecto ────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]   # /home/david/TFM
SRC  = ROOT / "src"
FIGS = ROOT / "artifacts" / "figs"
CSVS = ROOT / "artifacts" / "csv"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from crypto.pqc_wrapper import PQCProvider

# ── configuración de página ───────────────────────────────────────────────────
st.set_page_config(
    page_title="TFM — PQC en XMPP",
    page_icon="🔐",
    layout="wide",
)


@st.cache_resource
def get_pqc() -> PQCProvider:
    return PQCProvider()


# ── Datos compartidos entre sesiones (jurado ↔ presentador) ──────────────────

@dataclass
class ChatMessage:
    timestamp: str
    sender: str
    content: str
    alg_name: str
    sign_time_ms: float
    verify_time_ms: float
    sig_size_bytes: int
    pk_size_bytes: int
    verify_ok: bool


@st.cache_resource
def get_message_store() -> dict:
    """Estado compartido entre todas las sesiones Streamlit (jurado + presentador)."""
    return {"messages": deque(maxlen=50), "lock": threading.Lock()}


# ── Utilidades de red y QR ────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Devuelve la IP local de red (no loopback) para que el jurado pueda conectar."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def make_qr_bytes(url: str) -> bytes:
    """Genera un QR code como PNG en memoria."""
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


pqc = get_pqc()

SIG_OPTIONS: dict[str, str] = {
    "ML-DSA-65  (retículos, firma rápida)":           "ML-DSA-65",
    "SPHINCS+-SHA2-128s-simple  (hashes, sin retículos)": "SPHINCS+-SHA2-128s-simple",
}
KEM_ALG = "ML-KEM-768"

# ══════════════════════════════════════════════════════════════════════════════
# ENRUTAMIENTO — el jurado accede vía ?role=jury (enlace en el QR)
# ══════════════════════════════════════════════════════════════════════════════
_role = st.query_params.get("role", "presenter")

if _role == "jury":
    # ── Vista jurado (mobile-friendly) ───────────────────────────────────────
    st.title("📨 Enviar mensaje al presentador")
    st.caption("TFM — Criptografía Post-Cuántica en XMPP · Universidad de Málaga")
    st.info(
        "Tu mensaje será **firmado digitalmente con criptografía post-cuántica** "
        "antes de llegar al presentador. El presentador verifica la firma en tiempo real."
    )

    sender_name = st.text_input("Tu nombre (opcional)", placeholder="Miembro del tribunal")
    msg_content = st.text_area("Mensaje", placeholder="Escribe tu pregunta o mensaje aquí…", height=120)
    alg_choice  = st.selectbox("Algoritmo de firma PQC", list(SIG_OPTIONS))
    alg_name    = SIG_OPTIONS[alg_choice]

    st.caption(
        "**ML-DSA-65** — firma rápida (~0.3 ms), firma de ~3 KB  \n"
        "**SPHINCS+** — sin aritmética de retículos (~130 ms), firma de ~10 KB"
    )

    if st.button("📨  Enviar mensaje firmado", type="primary", use_container_width=True):
        if not msg_content.strip():
            st.warning("Escribe un mensaje antes de enviar.")
        else:
            with st.spinner(f"Firmando con {alg_name}…"):
                msg_bytes = msg_content.encode()
                res  = pqc.sign_message(alg_name, msg_bytes)
                vres = pqc.verify_signature(alg_name, msg_bytes, res.sig_b64, res.pk_b64)

                chat_msg = ChatMessage(
                    timestamp     = datetime.now().strftime("%H:%M:%S"),
                    sender        = sender_name.strip() or "Tribunal",
                    content       = msg_content,
                    alg_name      = alg_name,
                    sign_time_ms  = res.sign_time_ms,
                    verify_time_ms= vres.verify_time_ms,
                    sig_size_bytes= len(base64.b64decode(res.sig_b64)),
                    pk_size_bytes = len(base64.b64decode(res.pk_b64)),
                    verify_ok     = vres.ok,
                )

            store = get_message_store()
            with store["lock"]:
                store["messages"].appendleft(chat_msg)

            st.success(f"✅ Mensaje enviado y firmado con **{alg_name}**")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Firma",          f"{res.sign_time_ms:.2f} ms")
            c2.metric("Verificación",   f"{vres.verify_time_ms:.2f} ms")
            c3.metric("Tamaño firma",   f"{len(base64.b64decode(res.sig_b64)):,} B")
            c4.metric("Clave pública",  f"{len(base64.b64decode(res.pk_b64)):,} B")

            st.markdown("---")
            st.markdown("Puedes enviar otro mensaje si lo deseas. La firma anterior ya llegó al presentador.")

    st.stop()  # No renderizar la vista del presentador para el jurado


# ══════════════════════════════════════════════════════════════════════════════
# VISTA PRESENTADOR
# ══════════════════════════════════════════════════════════════════════════════
st.title("🔐 Criptografía Post-Cuántica en Mensajería XMPP")
st.caption(
    "**Universidad de Málaga · TFM · Demo en vivo para el tribunal**  ·  "
    "Algoritmos: ML-DSA-65 · SPHINCS+-SHA2-128s · ML-KEM-768 · RSA-2048 · ECDSA-P256 · ECDH-P256"
)

tab1, tab2, tab3 = st.tabs([
    "✍️  Firma PQC en directo",
    "🤝  Handshake Híbrido",

    "💬  Chat en Vivo",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — FIRMA PQC EN DIRECTO
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.header("Firma digital post-cuántica sobre un mensaje")
    st.markdown(
        "Elige un algoritmo, escribe cualquier mensaje y pulsa **Firmar**.  \n"
        "La operación se ejecuta en tiempo real con `liboqs` — sin tráfico de red."
    )

    col_in, col_out = st.columns(2, gap="large")

    with col_in:
        alg_label = st.selectbox("Algoritmo de firma", list(SIG_OPTIONS), key="t1_alg")
        alg_name  = SIG_OPTIONS[alg_label]
        msg_text  = st.text_area(
            "Mensaje",
            value="Este mensaje está protegido con criptografía post-cuántica resistente "
                  "a ataques de computadores cuánticos.",
            height=120,
            key="t1_msg",
        )
        do_sign = st.button("✍️  Firmar y verificar", type="primary", key="t1_sign")

    with col_out:
        if do_sign:
            if not msg_text.strip():
                st.warning("Escribe un mensaje primero.")
            else:
                msg_bytes = msg_text.encode()
                with st.spinner("Operando con liboqs…"):
                    res  = pqc.sign_message(alg_name, msg_bytes)
                    vres = pqc.verify_signature(alg_name, msg_bytes, res.sig_b64, res.pk_b64)

                if vres.ok:
                    st.success("✅ Firma VÁLIDA — el receptor puede autenticar el mensaje")
                else:
                    st.error("❌ Verificación fallida")

                c1, c2 = st.columns(2)
                c1.metric("Tiempo de firma",        f"{res.sign_time_ms:.3f} ms")
                c2.metric("Tiempo de verificación", f"{vres.verify_time_ms:.3f} ms")

                sig_raw = base64.b64decode(res.sig_b64)
                pk_raw  = base64.b64decode(res.pk_b64)

                c3, c4 = st.columns(2)
                c3.metric("Tamaño firma",         f"{len(sig_raw):,} bytes")
                c4.metric("Tamaño clave pública", f"{len(pk_raw):,} bytes")

                with st.expander("🔍 Primeros 48 bytes de la firma (hex)"):
                    st.code(sig_raw[:48].hex(" "), language=None)

    # ── comparativa directa ──────────────────────────────────────────────────
    st.divider()
    st.subheader("Comparación directa: ML-DSA-65 vs SPHINCS+")
    st.caption(
        "Ejecuta ambos algoritmos sobre el mismo mensaje y muestra los resultados uno al lado del otro."
    )

    if st.button("⚡  Comparar los dos algoritmos", key="t1_cmp"):
        sample = b"Mensaje de referencia: impacto de la criptografia post-cuantica en XMPP"
        rows: dict = {}
        with st.spinner("Calculando…"):
            for lbl, alg in SIG_OPTIONS.items():
                r = pqc.sign_message(alg, sample)
                v = pqc.verify_signature(alg, sample, r.sig_b64, r.pk_b64)
                rows[lbl] = {
                    "Firma (ms)":        round(r.sign_time_ms,   3),
                    "Verif. (ms)":       round(v.verify_time_ms, 3),
                    "Firma (bytes)":     len(base64.b64decode(r.sig_b64)),
                    "Clave pública (B)": len(base64.b64decode(r.pk_b64)),
                }

        st.dataframe(pd.DataFrame(rows).T, use_container_width=True)

        dsa_sign = rows[list(SIG_OPTIONS)[0]]["Firma (ms)"]
        sph_sign = rows[list(SIG_OPTIONS)[1]]["Firma (ms)"]
        dsa_sz   = rows[list(SIG_OPTIONS)[0]]["Firma (bytes)"]
        sph_sz   = rows[list(SIG_OPTIONS)[1]]["Firma (bytes)"]
        if dsa_sign > 0:
            st.info(
                f"SPHINCS+ tarda **×{sph_sign / dsa_sign:.0f}** más en firmar que ML-DSA-65 "
                f"y produce firmas **×{sph_sz / dsa_sz:.1f}** más grandes."
            )


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — HANDSHAKE HÍBRIDO
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.header("Protocolo de Handshake Híbrido: KEM post-cuántico + firma de identidad")
    st.markdown(
        "Emula el intercambio de claves completo entre emisor y receptor "
        "(operaciones criptográficas puras, sin tráfico XMPP).  \n"
        "El secreto compartido se establece con **ML-KEM-768** autenticado "
        "por una firma **PQC** de identidad que previene ataques man-in-the-middle."
    )

    col_proto, col_diagram = st.columns([2, 1])

    with col_diagram:
        st.markdown(
            """
**Flujo del protocolo:**

```
Emisor                    Receptor
  |                           |
  |── KEM keygen ──────────>  |
  |── Sig keygen ──────────>  |
  |── HELLO (pk_KEM + sig) ─> |
  |                    verify |
  |                   encaps  |
  | <── RESPONSE (ciphertext) |
  |  decaps                   |
  |                           |
  ╰── secreto compartido ─────╯
```
"""
        )

    with col_proto:
        sig_label = st.selectbox(
            "Algoritmo de firma de identidad",
            list(SIG_OPTIONS),
            key="t2_sig",
        )
        sig_alg = SIG_OPTIONS[sig_label]

        run_hs = st.button("🤝  Iniciar Handshake", type="primary", key="t2_run")

    if run_hs:
        nonce    = f"demo-{time.time_ns()}"
        ok_flag  = True
        t_start  = time.perf_counter()
        ops_rows: list[tuple] = []

        with st.status("Ejecutando protocolo de handshake híbrido…", expanded=True) as status_box:

            # ── Paso 1: KEM keygen ────────────────────────────────────────
            status_box.write("⏳ **Paso 1 / Emisor** — Generando par de claves KEM efímero (ML-KEM-768)…")
            kem_kp   = pqc.generate_kem_keypair(KEM_ALG)
            pk_kem_B = len(base64.b64decode(kem_kp.public_key_b64))
            status_box.write(
                f"✅ **KEM keygen** completado — {kem_kp.keygen_time_ms:.3f} ms · "
                f"Clave pública: **{pk_kem_B} bytes**"
            )
            ops_rows.append(("KEM keygen (ML-KEM-768)", kem_kp.keygen_time_ms, "Emisor"))

            # ── Paso 2: Sig keygen ────────────────────────────────────────
            status_box.write(
                f"⏳ **Paso 2 / Emisor** — Generando par de claves de firma ({sig_alg})…"
            )
            sig_kp = pqc.generate_signature_keypair(sig_alg)
            status_box.write(
                f"✅ **Sig keygen** completado — {sig_kp.keygen_time_ms:.3f} ms"
            )
            ops_rows.append((f"Sig keygen ({sig_alg})", sig_kp.keygen_time_ms, "Emisor"))

            # ── Paso 3: Firmar HELLO ──────────────────────────────────────
            status_box.write(
                "⏳ **Paso 3 / Emisor** — Construyendo y firmando mensaje HELLO "
                "(clave KEM pública + nonce)…"
            )
            hello_payload = json.dumps(
                {
                    "type": "hybrid_hello", "version": 1,
                    "kem_alg": KEM_ALG, "sig_alg": sig_alg,
                    "kem_pk_b64": kem_kp.public_key_b64, "nonce": nonce,
                },
                sort_keys=True, separators=(",", ":"),
            ).encode()
            sign_res   = pqc.sign_with_secret_key(
                sig_alg, hello_payload, sig_kp.secret_key_b64, sig_kp.public_key_b64,
            )
            hello_size = (
                len(hello_payload)
                + len(base64.b64decode(sign_res.sig_b64))
                + len(base64.b64decode(sign_res.pk_b64))
            )
            status_box.write(
                f"✅ **Firma HELLO** completada — {sign_res.sign_time_ms:.3f} ms · "
                f"Tamaño HELLO ≈ **{hello_size:,} bytes** *(cuerpo + firma + clave pública)*"
            )
            ops_rows.append(("Firma HELLO", sign_res.sign_time_ms, "Emisor"))

            # ── Paso 4: Receptor verifica ─────────────────────────────────
            status_box.write(
                "⏳ **Paso 4 / Receptor** — Verificando la firma del mensaje HELLO…"
            )
            vr = pqc.verify_signature(
                sig_alg, hello_payload, sign_res.sig_b64, sign_res.pk_b64,
            )
            if vr.ok:
                status_box.write(
                    f"✅ **Verificación HELLO** — VÁLIDA · {vr.verify_time_ms:.3f} ms  "
                    f"*(la clave KEM es auténtica, sin manipulación)*"
                )
                ops_rows.append(("Verificación HELLO", vr.verify_time_ms, "Receptor"))
            else:
                status_box.write(
                    "❌ **Verificación HELLO FALLIDA** — Firma inválida. Protocolo abortado."
                )
                status_box.update(label="Handshake fallido — firma inválida", state="error")
                ok_flag = False

            if ok_flag:
                # ── Paso 5: Receptor encapsula ────────────────────────────
                status_box.write(
                    "⏳ **Paso 5 / Receptor** — Encapsulando secreto compartido "
                    "con la clave KEM pública del emisor…"
                )
                enc  = pqc.encapsulate_secret(KEM_ALG, kem_kp.public_key_b64)
                ct_B = len(base64.b64decode(enc.ciphertext_b64))
                status_box.write(
                    f"✅ **Encapsulación KEM** completada — {enc.encaps_time_ms:.3f} ms · "
                    f"Ciphertext: **{ct_B} bytes** *(enviado al emisor)*"
                )
                ops_rows.append(("Encapsulación KEM", enc.encaps_time_ms, "Receptor"))

                # ── Paso 6: Emisor decapsula ──────────────────────────────
                status_box.write(
                    "⏳ **Paso 6 / Emisor** — Decapsulando el ciphertext para recuperar "
                    "el secreto compartido…"
                )
                dec = pqc.decapsulate_secret(
                    KEM_ALG, enc.ciphertext_b64, kem_kp.secret_key_b64,
                )
                status_box.write(
                    f"✅ **Decapsulación KEM** completada — {dec.decaps_time_ms:.3f} ms"
                )
                ops_rows.append(("Decapsulación KEM", dec.decaps_time_ms, "Emisor"))

                # ── Paso 7: Verificar coincidencia ────────────────────────
                status_box.write(
                    "⏳ **Paso 7** — Verificando que emisor y receptor derivaron "
                    "el mismo secreto compartido…"
                )
                h_sender = hashlib.sha256(base64.b64decode(dec.shared_secret_b64)).hexdigest()
                h_recvr  = hashlib.sha256(base64.b64decode(enc.shared_secret_b64)).hexdigest()
                secrets_match = h_sender == h_recvr

                if secrets_match:
                    status_box.write(
                        f"✅ **Secretos coinciden** — SHA-256: `{h_sender[:24]}…`  "
                        f"🔒 Canal seguro establecido"
                    )
                else:
                    status_box.write(
                        "❌ **Los secretos NO coinciden** — Error en la implementación."
                    )
                    ok_flag = False

                t_total_ms = (time.perf_counter() - t_start) * 1000.0
                status_box.update(
                    label=(
                        f"✅ Handshake completado en {t_total_ms:.1f} ms"
                        if ok_flag
                        else "❌ Handshake fallido"
                    ),
                    state="complete" if ok_flag else "error",
                )

        # ── Resumen post-handshake ────────────────────────────────────────
        if ok_flag and ops_rows:
            st.subheader("📋 Resumen del handshake")
            df_ops = pd.DataFrame(ops_rows, columns=["Operación", "Tiempo (ms)", "Ejecutado por"])
            df_ops["Tiempo (ms)"] = df_ops["Tiempo (ms)"].round(3)
            st.dataframe(df_ops, use_container_width=True, hide_index=True)

            m1, m2, m3 = st.columns(3)
            m1.metric("Tiempo total (cómputo puro)", f"{t_total_ms:.1f} ms")
            m2.metric("Algoritmo KEM",   KEM_ALG)
            m3.metric("Algoritmo firma", sig_alg)

            st.info(
                "💡 En el experimento XMPP real, el **RTT de red añade ~60-77 ms** adicionales "
                "sobre este tiempo de cómputo puro.  \n"
                "La firma de identidad garantiza que la clave KEM no ha sido sustituida "
                "por un atacante *(autenticación + secreto cuántico-seguro)*."
            )


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — CHAT EN VIVO (jurado ↔ presentador)
# ══════════════════════════════════════════════════════════════════════════════

@st.fragment(run_every="3s")
def _message_feed() -> None:
    """Fragment con auto-refresco cada 3 s — muestra los mensajes del jurado."""
    store    = get_message_store()
    messages = list(store["messages"])

    col_btn, col_count = st.columns([2, 1])
    col_btn.markdown("**Mensajes recibidos del tribunal** (actualización automática cada 3 s)")
    col_count.markdown(f"📨 **{len(messages)}** mensaje(s)")

    if not messages:
        st.info(
            "Esperando mensajes… Pide al jurado que escanee el QR de la izquierda "
            "con su móvil y envíe un mensaje firmado con PQC."
        )
        return

    for msg in messages:
        with st.container(border=True):
            col_status, col_body = st.columns([1, 5])
            with col_status:
                if msg.verify_ok:
                    st.success("✅\nVÁLIDA")
                else:
                    st.error("❌\nINVÁLIDA")
            with col_body:
                st.markdown(
                    f"**{msg.sender}** · `{msg.timestamp}` · "
                    f"<span style='color:gray;font-size:0.85em'>{msg.alg_name}</span>",
                    unsafe_allow_html=True,
                )
                st.markdown(f"> {msg.content}")
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Firma",         f"{msg.sign_time_ms:.2f} ms")
                c2.metric("Verificación",  f"{msg.verify_time_ms:.2f} ms")
                c3.metric("Firma (bytes)", f"{msg.sig_size_bytes:,}")
                c4.metric("PK (bytes)",    f"{msg.pk_size_bytes:,}")


with tab3:
    st.header("💬 Chat en Vivo — el tribunal envía mensajes firmados con PQC")
    st.markdown(
        "El jurado escanea el QR con su móvil, escribe un mensaje, "
        "elige el algoritmo de firma y pulsa **Enviar**.  \n"
        "El mensaje llega aquí **firmado y verificado en tiempo real** con `liboqs`."
    )

    # ── QR + instrucciones ────────────────────────────────────────────────────
    PUBLIC_URL = "https://reliance-adding-implementation-intro.trycloudflare.com"

    jury_url = f"{PUBLIC_URL}/?role=jury"
    qr_bytes = make_qr_bytes(jury_url)

    col_qr, col_steps = st.columns([1, 2], gap="large")

    with col_qr:
        st.image(qr_bytes, caption="Escanear con el móvil", width=220)
        st.markdown(f"**URL:** `{jury_url}`")
        st.caption(
            "Asegúrate de que Streamlit está escuchando en `0.0.0.0`:  \n"
            "`streamlit run src/demo_live/app.py --server.address 0.0.0.0`"
        )

    with col_steps:
        st.markdown(
            """
**Pasos para el jurado:**

1. Escanear el QR con la cámara del móvil (o introducir la URL en el navegador)
2. Escribir el nombre y el mensaje
3. Elegir el algoritmo: **ML-DSA-65** (rápido) o **SPHINCS+** (basado en hashes)
4. Pulsar **Enviar mensaje firmado**
5. En esta pantalla aparece el mensaje con los métricas de firma en tiempo real

**Lo que demuestra:**
- La firma se genera *en tiempo real* con `liboqs` (biblioteca Open Quantum Safe)
- El presentador verifica la firma sin necesidad de canal seguro previo
- Se puede comparar la latencia y el tamaño de ambos algoritmos sobre el mismo mensaje real
- Cambiando el algoritmo, el jurado verá directamente el impacto: SPHINCS+ tarda ~×400 más
"""
        )

    st.divider()

    # ── Botón para limpiar los mensajes ──────────────────────────────────────
    col_clear, _ = st.columns([1, 4])
    if col_clear.button("🗑️  Limpiar mensajes", key="t5_clear"):
        store = get_message_store()
        with store["lock"]:
            store["messages"].clear()
        st.rerun()

    # ── Feed de mensajes (auto-refresco vía @st.fragment) ────────────────────
    _message_feed()


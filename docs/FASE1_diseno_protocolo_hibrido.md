# FASE 1 — Diseño formal del protocolo híbrido (XMPP + ML-KEM + firmas PQ)

## 1) Objetivo y alcance (minimalista)

Diseñar un protocolo de **handshake híbrido, autenticado y medible** sobre XMPP en entorno local de laboratorio, con foco en:

- Intercambio de clave con **ML-KEM**.
- Autenticación de mensajes de control con **ML-DSA** o **SPHINCS+** (alternativas comparables).
- Integración en stanzas XML sin romper compatibilidad básica de parser.
- Trazabilidad temporal para medir coste criptográfico y de red.

**Fuera de alcance (explícito):** PKI completa, federación XMPP real, gestión de revocación, hardening de producción.

---

## 2) Entidades, notación y supuestos

### Entidades
- **A (iniciador)**: cliente Slixmpp que inicia sesión/handshake.
- **B (receptor)**: cliente Slixmpp destino.

### Material criptográfico
- Par de firma post-cuántica por entidad:
  - Variante 1: ML-DSA (`sk_sig`, `pk_sig`)
  - Variante 2: SPHINCS+ (`sk_sig`, `pk_sig`)
- ML-KEM para encapsulado/decapsulado:
  - `Encaps(pk_kem_B) -> (ct, ss)`
  - `Decaps(sk_kem_B, ct) -> ss`

### Supuestos experimentales mínimos
1. Cada cliente conoce previamente la **clave pública de firma** del otro (preconfigurada en fichero local).
2. Cada cliente conoce la **clave pública KEM** del receptor para iniciar handshake.
3. Canal XMPP puede observarse (Wireshark); por tanto, autenticación y no repudio de mensajes de control se hacen vía firma.
4. Se usa `session_id` único por ejecución para correlación y métricas.

---

## 3) Flujo formal del handshake (3 mensajes)

Diseño orientado a minimizar mensajes y mantener trazabilidad.

## Mensaje 1 — `pq:init` (A → B)
A genera:
- `session_id` (UUID v4)
- `nonce_a` (16 bytes aleatorios)
- timestamp local `t1_send`

Carga útil base:
```
{
  "session_id": ...,
  "from": JID_A,
  "to": JID_B,
  "kem_alg": "ML-KEM-<nivel>",
  "sig_alg": "ML-DSA-<nivel>" | "SPHINCS+-<param>",
  "nonce_a": b64(...),
  "ts": t1_send
}
```

Firma:
- `sig_a = Sign(sk_sig_A, Canonical(payload_base))`

A envía stanza `pq:init` con `payload_base + sig_a + pk_sig_A_id`.

## Mensaje 2 — `pq:reply` (B → A)
Al recibir `pq:init`, B:
1. Verifica firma de A con `pk_sig_A`.
2. Genera `nonce_b`.
3. Ejecuta `Encaps(pk_kem_B)` (si el diseño usa KEM de B publicada previamente, en este caso A encapsula; para mantener 3 mensajes y autenticación simétrica de control, adoptamos variante: **A encapsula en M1**).

> Para máxima simplicidad y evitar ambigüedad, se fija el flujo final recomendado:
> - **M1 incluye `ct` generado por A con `pk_kem_B`.**
> - B decapsula al recibir M1 y deriva `ss`.
> - M2 es confirmación autenticada.

Entonces, M2 contiene:
```
{
  "session_id": ...,
  "ack": "ok",
  "nonce_a": ...,
  "nonce_b": ...,
  "ts": t2_send
}
```

Firma:
- `sig_b = Sign(sk_sig_B, Canonical(payload_base_M2))`

B envía `pq:reply` firmado.

## Mensaje 3 — `pq:final` (A → B)
A verifica M2 y confirma finalización:
```
{
  "session_id": ...,
  "confirm": "ok",
  "nonce_b": ...,
  "ts": t3_send
}
```

Firma:
- `sig_a2 = Sign(sk_sig_A, Canonical(payload_base_M3))`

A envía `pq:final`. B verifica y marca sesión activa.

---

## 4) Derivación de clave de sesión

`ss` proviene de ML-KEM (encapsulado de A, decapsulado de B). Se deriva clave de sesión:

`K_session = HKDF(ss, salt = H(session_id || nonce_a || nonce_b), info = "xmpp-pq-chat-v1")`

Uso en Fase 1:
- No se cifra todo XMPP aún (evita ampliar alcance).
- `K_session` se usa para:
  1) tag opcional de integridad en payloads experimentales,
  2) dejar preparado el terreno para fase posterior de protección de contenido.

---

## 5) Estructura XML de stanzas (namespace propio)

Namespace propuesto:

`xmlns:pq="urn:tfm:pq:1"`

Plantilla `pq:init`:
```xml
<message from='A' to='B' type='chat' id='...'>
  <pq:init xmlns:pq='urn:tfm:pq:1' session_id='...'
           kem='ML-KEM-768' sig='ML-DSA-65' ts='...'>
    <pq:nonce_a>...</pq:nonce_a>
    <pq:ct>...</pq:ct>
    <pq:sig>...</pq:sig>
    <pq:key_id>alice_sig_key_01</pq:key_id>
  </pq:init>
</message>
```

Reglas XML minimalistas:
1. Campos binarios siempre en Base64.
2. Un único bloque `pq:*` por stanza de control.
3. Campos obligatorios: `session_id`, `ts`, `sig`, `key_id`, nonces según fase.
4. Si falta campo obligatorio o firma inválida: respuesta de error local y descarte.

---

## 6) ¿Qué se firma exactamente?

Para evitar problemas de serialización XML, **no se firma el XML bruto**. Se firma un objeto canónico (JSON canónico):

1. Selección de campos semánticos obligatorios.
2. Orden lexicográfico de claves.
3. UTF-8 estricto.
4. Sin espacios superfluos.
5. `sig` excluida del material firmado.

Material firmado recomendado por tipo:
- `pq:init`: `session_id, from, to, kem_alg, sig_alg, nonce_a, ct, ts`
- `pq:reply`: `session_id, from, to, ack, nonce_a, nonce_b, ts`
- `pq:final`: `session_id, from, to, confirm, nonce_b, ts`

Esta decisión hace el diseño defendible y reproducible en evaluación experimental.

---

## 7) Flujo de estados (máquina mínima)

### Iniciador A
- `IDLE` → envía `pq:init` → `WAIT_REPLY`
- `WAIT_REPLY` + `pq:reply` válido → envía `pq:final` → `ESTABLISHED`
- Error de verificación/timeout → `FAILED`

### Receptor B
- `IDLE` + `pq:init` válido → decapsula + envía `pq:reply` → `WAIT_FINAL`
- `WAIT_FINAL` + `pq:final` válido → `ESTABLISHED`
- Error de verificación/timeout → `FAILED`

Timeout recomendado experimental: 2–5 s configurable.

---

## 8) Campos para métricas (ya embebidos desde Fase 1)

Incluir en cada mensaje de control:
- `session_id`
- `msg_type`
- `seq`
- `ts_send_local`
- `payload_len_bytes`
- `sig_len_bytes`
- `ct_len_bytes` (solo donde aplique)

Con esto, Fase 2 y Fase 3 podrán calcular RTT y overhead sin rediseñar protocolo.

---

## 9) Criterios de aceptación de Fase 1

La Fase 1 se considera cerrada cuando exista especificación estable con:
1. Handshake de 3 mensajes definido.
2. Esquema de stanzas XMPP con namespace propio.
3. Material firmado definido y canónico.
4. Estados y errores principales definidos.
5. Campos de métricas incluidos en el diseño.

---

## 10) Decisiones de diseño y justificación académica breve

- **3 mensajes**: compromiso entre simplicidad y autenticación mutua de control.
- **Firma de payload canónico, no XML bruto**: elimina variaciones de serialización.
- **Claves públicas preconfiguradas**: apropiado para entorno controlado de TFM.
- **Sin cifrado completo de stanzas en esta fase**: mantiene alcance en rendimiento de primitives PQ y overhead medible.

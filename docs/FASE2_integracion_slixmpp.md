# FASE 2 — Integración con Slixmpp (implementada)

## Objetivo
Integrar el handshake híbrido en clientes Slixmpp sin romper parser XML ni el flujo normal de sesión.

## Resultado implementado
- Namespace propio: `urn:tfm:pq:1`.
- Stanzas de control (encapsuladas en `<message type='chat'>`, no en `<iq>`):
  - `<pq:init>` con payload+firma+pk.
  - `<pq:reply>` con payload+firma+pk.
  - `<pq:final>` con payload+firma+pk.
- Validación robusta:
  - Comprobación de campos mínimos por tipo de mensaje.
  - Verificación de firma sobre JSON canónico.
  - Manejo de errores y timeouts sin tumbar el proceso.

## Medición temporal incorporada
- Emisor:
  - `kem_encap_ms`
  - `sign_init_ms`
  - `verify_reply_ms`
  - `rtt_ms`
- Receptor:
  - `verify_init_ms`
  - `decap_ms`
  - `sign_reply_ms`

## Ficheros clave
- `src/protocol/hybrid_protocol.py`
- `src/demoB/emisor_hybrid.py`
- `src/demoB/receptor_hybrid.py`
- `src/demoB/setup_keys.py`

## Criterio de cierre
La fase queda cerrada cuando un handshake completo produce registros `ok=1` en sender/receiver CSV.

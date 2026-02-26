# FASE 5 — Análisis final y conclusiones (framework implementado)

## Interpretación del overhead
- Analizar incremento de tamaño de stanza por algoritmo.
- Relacionar tamaño de firma y tamaño total de stanza.
- Evaluar impacto en RTT bajo red local estable.

## Conclusiones defendibles
Son defendibles si:
1. Se reportan intervalos (no solo medias).
2. Se explicita variabilidad experimental.
3. Se comparan algoritmos en mismas condiciones.

## Límites a declarar
- Entorno local controlado (no WAN/federación real).
- Sin PKI completa ni revocación.
- Implementación centrada en handshake y métricas de rendimiento.
- Dependencia de stack local (`Prosody`, `slixmpp`, `liboqs`).

## Salida automática para memoria
- Tabla resumen en `artifacts/csv/phase4_summary.csv`.
- Informe Markdown en `artifacts/reports/phase4_summary.md`.

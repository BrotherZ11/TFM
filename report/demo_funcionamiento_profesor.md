# Demo funcional para el profesor


## Mensaje corto de apertura

Puedes empezar así:

> He preparado un entorno experimental donde integro criptografía post-cuántica en XMPP. La demo enseña dos partes: qué se ha implementado en el código y cómo se ejecuta el flujo real de envío, autenticación y acuerdo de clave.

## Orden recomendado de la demo

Hazlo en este orden para que se entienda bien:

1. Explicar el objetivo general del proyecto.
2. Enseñar la estructura del repositorio.
3. Enseñar los componentes principales del código.
4. Ejecutar una demo en vivo.
5. Explicar qué acaba de pasar internamente.

## 1. Qué has implementado

Debes explicarlo como cuatro bloques claros.

### Bloque A. Capa criptográfica reutilizable

Está en src/crypto/pqc_wrapper.py.

Qué hace:

- firma mensajes con algoritmos PQC,
- verifica firmas,
- genera pares de claves de firma,
- genera pares de claves KEM,
- encapsula secretos compartidos,
- desacapsula secretos.

Cómo explicarlo:

> Esta capa abstrae el uso de oqs-python para que el resto del proyecto no dependa de llamadas criptográficas dispersas. Así separo la lógica de seguridad de la lógica de mensajería y de benchmark.

### Bloque B. Demo de firmas sobre XMPP

Aquí el emisor firma el cuerpo de un mensaje XMPP y mete en la stanza XML:

- el algoritmo usado,
- la firma,
- la clave pública.

El receptor:

- recibe la stanza,
- extrae el bloque PQC,
- reconstruye el mensaje,
- verifica la firma,
- informa del resultado y mide tiempos.

Cómo explicarlo:

> Esta parte demuestra autenticidad e integridad del mensaje a nivel de aplicación usando primitivas post-cuánticas.

### Bloque C. Handshake híbrido autenticado

Esta es la parte más interesante para enseñar.

Qué has implementado:

- uso de ML-KEM-768 para establecer un secreto compartido,
- autenticación del mensaje inicial mediante firma PQC,
- transporte del flujo a través de XMPP,
- validación de identidad por certificado o por huella.

Cómo explicarlo:

> El emisor inicia un HELLO con material KEM efímero y lo firma. El receptor verifica identidad y autenticidad. Si todo es correcto, encapsula el secreto y responde. Ambos extremos terminan con el mismo secreto compartido.

### Bloque D. Instrumentación y métricas

Además del funcionamiento, has implementado medición de:

- tiempos de firma y verificación,
- tiempos de encapsulación y desacapsulación,
- RTT del intercambio,
- tamaño de stanzas y mensajes,
- consistencia del secreto compartido.

Cómo explicarlo:

> No me limito a que funcione. También capturo métricas para evaluar el coste real de integrar PQC en un flujo de mensajería.

## 2. Qué enseñar del código

No enseñes demasiados ficheros. Solo estos.

### Primero: src/crypto/pqc_wrapper.py

Qué decir:

> Aquí centralizo toda la lógica criptográfica. Se ve la separación entre firma, verificación, generación de claves y operaciones KEM.

### Segundo: src/demo2_hybrid_kem_signed/protocol.py

Qué decir:

> Aquí está definido el formato lógico del HELLO y lo que exactamente se firma. Esto es importante porque la demo no firma un blob arbitrario, sino una estructura estable y serializada.

### Tercero: scripts/run_all_demos.sh

Qué decir:

> Este script automatiza la ejecución completa. Aunque hoy haga una demo puntual, el proyecto ya está preparado para ejecución reproducible por fases.

## 3. Demo en vivo recomendada

La mejor demo para explicar funcionamiento es la de handshake híbrido sobre XMPP en modo cert.

Motivo:

- enseña mensajería real,
- enseña autenticación,
- enseña acuerdo de clave,
- enseña modelo de confianza,
- y enseña intercambio completo extremo a extremo.

## Comandos exactos

### Terminal 1

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/receptor_hybrid_bench.py --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

### Terminal 2

```bash
cd /home/david/TFM
source venv/bin/activate
PYTHONPATH=src venv/bin/python src/demo2_hybrid_kem_signed/emisor_hybrid_bench.py --verify-mode cert --host 127.0.0.1 --port 5222 --startup-timeout 20
```

## 4. Qué tienes que ir diciendo mientras corre

### Paso 1. Arranca el receptor

Frase útil:

> Primero arranco el receptor, que queda escuchando y preparado para validar la identidad del emisor y completar el handshake.

### Paso 2. Arranca el emisor

Frase útil:

> Ahora el emisor genera el material efímero del KEM, construye un HELLO y lo autentica con firma post-cuántica.

### Paso 3. Receptor valida

Frase útil:

> El receptor comprueba que el mensaje inicial sea auténtico. En este modo, esa confianza se basa en un certificado X.509 real con extensiones privadas para transportar la parte PQC.

### Paso 4. Receptor encapsula

Frase útil:

> Si la validación es correcta, el receptor encapsula el secreto compartido con ML-KEM y responde al emisor.

### Paso 5. Emisor desacapsula

Frase útil:

> El emisor desacapsula la respuesta y ambos extremos terminan con el mismo secreto. A la vez, el sistema registra tiempos y tamaños de todo el proceso.

## 5. Explicación técnica paso a paso

Si el profesor te pide detalle, esta es la explicación buena.

### Flujo lógico

1. El emisor genera un par de claves KEM efímero.
2. Construye un mensaje HELLO con algoritmo, nonce, clave pública KEM y huella del certificado.
3. Firma esa estructura con el algoritmo PQC seleccionado.
4. Envía el HELLO a través de XMPP.
5. El receptor recibe el mensaje y verifica la firma.
6. El receptor valida el modelo de confianza.
7. Si todo es correcto, encapsula un secreto con la clave pública KEM del emisor.
8. Devuelve el ciphertext de encapsulación.
9. El emisor desacapsula y obtiene el mismo secreto.
10. Ambos lados registran métricas.

### Por qué es híbrido

Frase útil:

> Es híbrido porque combina establecimiento de secreto mediante KEM con autenticación por firma. No es solo cifrado, ni solo firma: integra ambas piezas en el mismo protocolo experimental.

### Por qué usas XMPP

Frase útil:

> XMPP me permite probar el impacto de estas primitivas en un protocolo de mensajería realista, con serialización XML, intercambio de stanzas y latencia de red, en vez de quedarme en una simulación puramente local.

### Por qué usas certificado con extensiones privadas

Frase útil:

> El certificado es X.509 real, pero la parte PQC viaja en extensiones privadas. Eso me permite modelar una identidad transportable y verificable sin depender de una PKI PQC totalmente estandarizada en Python.

## 6. Qué NO necesitas alargar demasiado

En esta reunión no hace falta profundizar mucho en:

- pruebas estadísticas,
- comparación extensa entre todos los CSV,
- gráficas,
- PCAP,
- automatización completa.

Solo enséñalo si el profesor te lo pide.

## 7. Preguntas probables y respuesta breve

### “¿Qué has implementado tú exactamente?”

Respuesta:

> La integración de firmas PQC y handshake híbrido sobre XMPP, la lógica de autenticación y validación, la capa reutilizable de operaciones criptográficas, y la instrumentación de métricas para medir comportamiento real.

### “¿Qué parte es la más importante?”

Respuesta:

> La más representativa es el handshake híbrido sobre XMPP, porque junta identidad, autenticación, acuerdo de clave y transporte real en un único flujo ejecutable.

### “¿Qué demuestra la demo?”

Respuesta:

> Demuestra que el flujo funciona de extremo a extremo y que la criptografía post-cuántica se puede integrar de forma operativa en una aplicación de mensajería, no solo en un benchmark aislado.

### “¿Cuál es la limitación principal?”

Respuesta:

> Sigue siendo un entorno experimental. La principal mejora sería endurecer la parte de identidad y PKI y acercarlo más a un despliegue real.

## 8. Cierre recomendado

Termina así:

> Lo que quería demostrar con esta demo era que la integración no es solo teórica. Ya existe una implementación funcional, modular y medible, donde se ve cómo intervienen las primitivas PQC dentro del flujo real de mensajería y establecimiento de clave.
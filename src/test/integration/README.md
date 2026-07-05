# Pruebas de integración end-to-end

Pruebas del proxy completo contra procesos reales, complementarias a los tests
unitarios de `src/test/` (que prueban los handlers aislados con stubs). No
requieren red externa: el "origen" es un `http.server` de Python local.

## `relay_integrity.sh`

Valida el relay bidireccional con tráfico real: baja un archivo de 5MB
a través del proxy y compara `sha256sum` contra el original (el archivo es ≫
que los buffers de 2048 bytes, así que ejercita I/O parcial y backpressure).
Corre dos transferencias:

1. con `curl --socks5-hostname` (el camino típico de un cliente real), y
2. con `half_close_client.py`, que además hace un **half-close real**.

```sh
./src/test/integration/relay_integrity.sh
```

Recompila el server, usa puertos dinámicos (no colisiona entre corridas),
espera a que los procesos escuchen antes de transferir, aplica timeouts y
limpia todo al salir. Sale con `0` si ambas descargas llegan íntegras, `1` si
una transferencia falla o llega corrupta (distinguiendo si un proceso murió en
el medio), `2` si falta una dependencia (`curl`, `python3`, `sha256sum`) o
falla el build.

## `multiip_fallback.sh`

Valida el connect robusto multi-IP: cuando un FQDN resuelve a varias
direcciones, el proxy prueba cada una hasta que alguna funcione, y responde el
REP correcto si todas fallan. El truco es `multiip_shim.c` (LD_PRELOAD sobre el
proxy): resuelve nombres mágicos a listas controladas de loopbacks, y como el
`http.server` de origen escucha **solo** en `127.0.0.1`, las demás direcciones
(`127.0.0.2/3`) rechazan con `ECONNREFUSED` — direcciones "caídas"
determinísticas, sin red externa ni tocar `/etc/hosts`. Dos casos:

1. `multiip-fallback.test` → `[127.0.0.2 caída, 127.0.0.1 viva]`: la descarga
   vía `curl --socks5-hostname` llega íntegra por la segunda dirección.
2. `multiip-allrefused.test` → ambas caídas: `rep_client.py` verifica REP
   `0x05` (connection refused) y que el proxy cierra tras el reply.

```sh
./src/test/integration/multiip_fallback.sh
```

Mismas garantías que `relay_integrity.sh`: recompila server y shim, puertos
dinámicos, espera de listen, timeouts y cleanup. Sale `0` si ambos casos
pasan, `1` si el fallback no anduvo o el REP fue otro, `2` por dependencias o
build.

## `multiip_shim.c`

Shim de `getaddrinfo`/`freeaddrinfo` que fabrica las listas multi-IP del test
anterior. Construye **sus propios** nodos (un malloc por candidato) y libera
él mismo las listas que fabricó (registro de cabezas bajo mutex, passthrough
al `freeaddrinfo` real para las ajenas): mezclar nodos propios con listas de
la libc y liberarlos cruzados no está garantizado por POSIX.

## `rep_client.py`

Cliente SOCKS5 mínimo que expone lo que curl esconde: **qué** REP devolvió el
proxy ante un CONNECT rechazado. Negocia hello + request, compara el byte REP
del REPLY contra el esperado y, si es de error, valida que el proxy cierra la
conexión después (RFC 1928 §6). Lo invoca `multiip_fallback.sh`, pero sirve
solo:

```sh
python3 src/test/integration/rep_client.py \
    <puerto-proxy> <dest-host> <dest-port> <rep-esperado>
```

## `half_close_client.py`

Cliente SOCKS5 mínimo que ejercita el half-close que curl nunca hace: CONNECT,
manda un `GET` HTTP/1.0, cierra su escritura con `shutdown(SHUT_WR)` y valida
que igual recibe la respuesta completa hasta EOF (el proxy tiene que propagar
el FIN sin perder bytes en vuelo y mantener vivo el sentido origen→cliente).
Lo invoca `relay_integrity.sh`, pero también sirve solo:

```sh
python3 src/test/integration/half_close_client.py \
    <puerto-proxy> <dest-host> <dest-port> <path> <archivo-salida>
```

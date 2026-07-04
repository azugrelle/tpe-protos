# Pruebas de integración end-to-end

Pruebas del proxy completo contra procesos reales, complementarias a los tests
unitarios de `src/test/` (que prueban los handlers aislados con stubs). No
requieren red externa: el "origen" es un `http.server` de Python local.

## `relay_integrity.sh`

Valida el relay bidireccional de T41 con tráfico real: baja un archivo de 5MB
a través del proxy y compara `sha256sum` contra el original (el archivo es ≫
que los buffers de 2048 bytes, así que ejercita I/O parcial y backpressure).
Corre dos transferencias:

1. con `curl --socks5-hostname` (el flujo del hito M3), y
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

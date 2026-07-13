# Pruebas de integración end-to-end

Pruebas del proxy completo contra procesos reales, complementarias a los tests
unitarios de `src/test/` (que prueban los handlers aislados con stubs). No
requieren red externa: el "origen" es un `http.server` de Python local.

## `relay_integrity.sh`

Valida el relay bidireccional con tráfico real: baja un archivo de 5MB
a través del proxy y compara `sha256sum` contra el original (el archivo es ≫
que los buffers de una conexión, así que ejercita I/O parcial y backpressure).
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

## `shutdown_drain.sh`

Valida el apagado ordenado ante señales de terminación. Baja el archivo de 5MB
con `curl --limit-rate` (para que la transferencia dure varios segundos y haya
ventana para señalar en el medio) y cubre los dos caminos:

1. **drenado**: `SIGTERM` a mitad de transferencia → el proxy rechaza
   conexiones nuevas (los pasivos ya cerraron) pero la transferencia en curso
   termina íntegra (`sha256sum` igual al original), y el proceso sale solo con
   `exit 0` apenas queda sin conexiones vivas.
2. **corte forzado**: una 2ª `SIGTERM` a mitad de drenado → la transferencia
   se corta ya (no llega completa) y el proxy igual sale con `exit 0`.

```sh
./src/test/integration/shutdown_drain.sh
```

Mismas garantías que `relay_integrity.sh`: recompila el server, puertos
dinámicos, espera de listen, timeouts (incluida una cota para "el proxy debe
salir solo") y cleanup. Sale `0` si ambos casos pasan, `1` si el drenado
cortó la transferencia, aceptó conexiones nuevas, no salió solo o devolvió un
exit code distinto de 0, `2` por dependencias o build.

## `config_hot.sh`

Valida que `CONFIG` afecte al proxy en caliente, sin reiniciar el proceso, con
la matriz de aplicación distinta por parámetro:

1. **`timeout`** (aplica a **todas** las conexiones vivas): `CONFIG timeout 3`
   + una conexión muda al proxy → se cierra sola dentro de una ventana
   generosa. Después, `CONFIG timeout 30` sobre el **mismo** proceso + una
   conexión nueva → sobrevive más allá de lo que aguantaba con el valor
   viejo, probando que el cambio se leyó sin reiniciar.
2. **`buf_size`** (aplica solo a conexiones **nuevas**): a mitad de una
   transferencia de 5MB en curso, `CONFIG buf_size 4096` → la transferencia
   viva (con sus buffers originales) termina íntegra (`sha256sum`), y una
   transferencia nueva iniciada después también llega íntegra con el tamaño
   actualizado.

```sh
./src/test/integration/config_hot.sh
```

Mismas garantías que los demás: recompila server y cliente, puertos
dinámicos, espera de listen y cleanup. Sale `0` si ambos casos pasan, `1` si
una conexión no se cerró/sobrevivió como se esperaba o una transferencia
llegó corrupta, `2` por dependencias o build.

## `monitor_session.sh`

Valida el cliente de monitoreo contra el server real, punta a punta. Es el
único script cableado a make (`make integration-test`). Cuatro escenarios:

1. **sesión completa via one-shot**: `stats`, `users`, `connections` y
   `config` (válido e inválido) con su contrato de exit codes — `0` si el
   server respondió `+OK`, `1` ante `-ERR` o login fallido (con stdout vacío:
   el rechazo va por stderr).
2. **uso inválido local**: aridad incorrecta o comando desconocido salen con
   `2` **sin tocar la red** (se corre contra un puerto sin listener para
   probar que no conecta).
3. **REPL scripteado por stdin**: sesión multi-comando por pipe; un comando
   desconocido no corta la sesión, el `quit` final devuelve `0`, stdout queda
   solo con respuestas (prompts a stderr) y el password nunca se re-imprime.
4. **caída del server entre dos comandos**: coordinado con un FIFO (un
   heredoc entregaría todo el input junto y no habría forma de matar el
   server "en el medio"); el cliente debe reportar la desconexión con un
   mensaje claro y salir con exactamente `1` (≥ 128 sería un crash).

```sh
make integration-test        # o directo:
./src/test/integration/monitor_session.sh
```

Mismas garantías que los demás: recompila server y cliente, puertos
dinámicos, espera de listen, timeouts y cleanup. Sale `0` si los cuatro
escenarios pasan, `1` si una aserción falla, `2` por dependencias o build.

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

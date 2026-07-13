# Pruebas de estrés

Scripts para las mediciones de performance del informe (máxima concurrencia,
throughput y tamaño de buffer). A diferencia de `integration/`, acá el
resultado principal no es pasa/no-pasa sino **números**: cada script termina
con un resumen listo para pegar en el informe.

Condiciones de medición:

- Correr **sin valgrind** y con la máquina lo más ociosa posible.
- Todo es loopback contra orígenes locales: se mide el proxy, no la red.
- Registrar junto a los números: hardware (CPU/RAM), entorno (WSL2 o Linux
  nativo), versión de `gcc`, los flags del build y cuántas corridas se
  hicieron. `throughput.sh` imprime al final la versión de `gcc` y los flags
  reales leídos de `Makefile.inc`, para no transcribirlos a mano (hoy es
  `-g`, sin optimización, pero lo que vale es lo que imprime la corrida).
- Repetir la corrida completa un par de veces para confirmar que los números
  son estables antes de volcarlos al informe.

## `max_connections.sh`

Mide la concurrencia: abre `TARGET` túneles SOCKS5 autenticados sostenidos
(500 por defecto, el mínimo de la consigna) con `concurrent_tunnels.py` (un
solo proceso cliente) contra `hold_server.py` (origen que mantiene las
conexiones vivas), y con los túneles abiertos contrasta el conteo con
`CONNECTIONS` del monitoreo, sigue abriendo hasta el primer rechazo para
medir el **techo real** (teórico: 511, acotado por `FD_SETSIZE` de
`select()`), verifica que el rechazo sea limpio (TCP aceptado y cerrado sin
reply SOCKS) y que el server saturado siga relayando, y que al cerrar
túneles se vuelvan a aceptar conexiones.

```sh
./src/test/stress/max_connections.sh            # TARGET=500
TARGET=200 ./src/test/stress/max_connections.sh # corrida mas liviana
```

Requiere `ulimit -n` ≥ `2*TARGET + 100` (el script lo verifica y avisa).
Sube el `timeout` de inactividad a 3600 antes de abrir los túneles, porque
quedan ociosos durante la prueba. Sale `0` si todas las verificaciones
pasan, `1` si alguna falla, `2` por dependencias, build o `ulimit`.

## `throughput.sh`

Mide el rendimiento sirviendo un archivo desde tmpfs con un `http.server`
local: descarga directa (baseline), a través del proxy con una conexión,
matriz de `N` descargas paralelas, y barrido de `buf_size` cambiado en
caliente vía `CONFIG` (aplica a conexiones nuevas: cada `curl` posterior ya
usa el valor nuevo, sin recompilar ni reiniciar — al final vuelve al default
de 8192).

```sh
./src/test/stress/throughput.sh
# corrida liviana para probar el script:
FILE_MB=5 RUNS=1 PARALLEL_SET="1 2" BUF_SIZES="2048 8192" ./src/test/stress/throughput.sh
```

Variables: `FILE_MB` (100), `RUNS` (3, se reporta la mediana),
`PARALLEL_SET` (`1 5 10 25 50`), `BUF_SIZES` (`512 ... 131072`). Las
velocidades son el `%{speed_download}` de `curl`, convertidas a MB/s.

**Ojo con el origen:** `python3 -m http.server` es multithread pero lento;
el script compara la descarga directa contra la proxied y avisa si el origen
parece ser el cuello de botella (proxy ≥ 90% del directo). En ese caso los
números de overhead son un piso, no una medición del proxy: conviene un
origen más rápido (por ejemplo `nginx`) y anotarlo en el informe.

Sale `0` si todas las transferencias completaron, `1` si alguna falló, `2`
por dependencias o build.

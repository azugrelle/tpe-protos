#!/bin/bash
#
# Prueba de estres: throughput y tamanio de buffer.
#
# Contra un origen HTTP local que sirve un archivo desde tmpfs (el disco no
# juega), mide:
#   1. descarga directa (baseline sin proxy),
#   2. descarga a traves del proxy (overhead con una conexion),
#   3. degradacion con N descargas paralelas por el proxy,
#   4. throughput segun buf_size, cambiado en caliente via CONFIG (aplica a
#      conexiones nuevas: cada curl posterior ya usa el valor nuevo, sin
#      recompilar ni reiniciar).
#
# Variables (con defaults pensados para una corrida completa razonable):
#   FILE_MB=100                       tamanio del archivo
#   RUNS=3                            repeticiones por medicion (se reporta la mediana)
#   PARALLEL_SET="1 5 10 25 50"       valores de N para la matriz de paralelismo
#   BUF_SIZES="512 1024 2048 4096 8192 16384 32768 65536 131072"
#
# La salida son tablas listas para pegar en el informe. Las velocidades son
# las que reporta curl (%{speed_download}), en bytes por segundo.
# Sale 0 si todo ok, 1 si una transferencia fallo, 2 si falta una dependencia
# o fallo el build.
#
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
. "$HERE/../lib.sh"
FILE_MB="${FILE_MB:-100}"
RUNS="${RUNS:-3}"
PARALLEL_SET="${PARALLEL_SET:-1 5 10 25 50}"
BUF_SIZES="${BUF_SIZES:-512 1024 2048 4096 8192 16384 32768 65536 131072}"
XFER_TIMEOUT=300
ADMIN="admin:secreto"
PROXY_USER="alice"
PROXY_PASS="pass1"

# el default se lee del header, no se transcribe: la medicion "a traves del
# proxy" se rotula con el buf_size real con el que corrio, y el barrido lo
# restaura al terminar
DEFAULT_BUF="$(sed -n 's/^#define CONFIG_BUF_SIZE_DEFAULT[[:space:]]*//p' \
                   "$REPO/src/shared/include/config.h")"
[ -n "$DEFAULT_BUF" ] || { echo "no se pudo leer CONFIG_BUF_SIZE_DEFAULT" >&2; exit 2; }

for dep in curl python3 dd awk sort; do
    command -v "$dep" >/dev/null 2>&1 || { echo "falta $dep" >&2; exit 2; }
done

make -C "$REPO" server client >/dev/null || { echo "fallo el build" >&2; exit 2; }

# el archivo se sirve desde tmpfs para que el disco no sea el cuello de
# botella; si /dev/shm no esta, mktemp comun (y anotarlo al interpretar)
TMP="$(mktemp -d /dev/shm/stress.XXXXXX 2>/dev/null || mktemp -d)"
case "$TMP" in /dev/shm/*) ;; *) echo "aviso: sin /dev/shm, el archivo no queda en tmpfs" ;; esac

PROXY_PID=""
HTTP_PID=""
cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
    [ -n "$HTTP_PID" ]  && kill "$HTTP_PID"  2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

PROXY_PORT="$(free_port)"
MGMT_PORT="$(free_port)"
HTTP_PORT="$(free_port)"

# El tamanio del archivo es parte de la medicion: en un container con el /dev/shm
# default (64MB) y FILE_MB=100, mktemp funciona pero dd muere por ENOSPC y deja un
# archivo truncado. Sin chequear status Y tamanio, el resto de la prueba mide
# transferencias de un tamanio distinto al que despues se reporta en el informe.
EXPECT_BYTES=$((FILE_MB * 1048576))
dd if=/dev/urandom of="$TMP/big.bin" bs=1M count="$FILE_MB" status=none \
    || { echo "dd no pudo generar el archivo de ${FILE_MB}MB en $TMP" >&2; exit 2; }
ACTUAL_BYTES="$(wc -c < "$TMP/big.bin")"
[ "$ACTUAL_BYTES" -eq "$EXPECT_BYTES" ] || {
    echo "el archivo quedo en $ACTUAL_BYTES bytes y se esperaban $EXPECT_BYTES" >&2
    echo "  (se lleno $TMP? probar con un FILE_MB mas chico)" >&2
    exit 2
}

python3 -m http.server "$HTTP_PORT" --directory "$TMP" >/dev/null 2>&1 &
HTTP_PID=$!
# el log del server no va a /dev/null: fail() muestra su tail para diagnosticar
SERVER_LOG="$TMP/server.log"
"$REPO/bin/server" -p "$PROXY_PORT" -P "$MGMT_PORT" \
    -a "$ADMIN" -u "$PROXY_USER:$PROXY_PASS" >"$SERVER_LOG" 2>&1 &
PROXY_PID=$!

wait_listen "$HTTP_PID"  "$HTTP_PORT"  "http.server" || exit 2
wait_listen "$PROXY_PID" "$PROXY_PORT" "proxy"       || exit 2
wait_listen "$PROXY_PID" "$MGMT_PORT"  "monitoreo"   || exit 2

URL="http://127.0.0.1:$HTTP_PORT/big.bin"

# Imprime la velocidad de una descarga SOLO si la transferencia fue completa; si
# fallo, devuelve != 0 sin imprimir nada. Los tres chequeos son necesarios:
#   --fail    sin el, un 404 baja la pagina de error, sale 0 y reporta una
#             velocidad plausible (se mediria el error, no el archivo);
#   $rc       curl imprime igual su linea -w cuando falla (una conexion rechazada
#             sale 7 y escribe "0"), asi que la linea sola no prueba exito;
#   speed > 0 defensa final: una muestra en 0 no es una medicion.
curl_speed() {
    local out rc
    out="$(curl -sSfo /dev/null --max-time "$XFER_TIMEOUT" \
                -w '%{speed_download}\n' "$@" "$URL")"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "curl fallo (codigo $rc)" >&2
        return 1
    fi
    if [ -z "$out" ] || ! awk -v s="$out" 'BEGIN { exit !(s > 0) }'; then
        echo "curl reporto una velocidad no medible: '$out'" >&2
        return 1
    fi
    echo "$out"
}

curl_direct() {
    curl_speed
}
curl_proxied() {
    curl_speed --socks5-hostname "$PROXY_USER:$PROXY_PASS@127.0.0.1:$PROXY_PORT"
}

median() {  # mediana de numeros, uno por linea de stdin
    sort -n | awk '{ v[NR] = $1 } END {
        if (NR == 0) exit 1
        if (NR % 2)  printf "%.0f\n", v[(NR + 1) / 2]
        else         printf "%.0f\n", (v[NR / 2] + v[NR / 2 + 1]) / 2 }'
}
mbs() { awk -v b="$1" 'BEGIN { printf "%.1f", b / 1048576 }'; }

runs_speeds() {  # corre $RUNS veces la funcion $1; falla si falla cualquier corrida
    local fn=$1
    for _ in $(seq "$RUNS"); do
        "$fn" || return 1
    done
}
runs_median() {  # corre $RUNS veces la funcion $1 y devuelve la mediana
    local out
    out="$(runs_speeds "$1")" || return 1
    echo "$out" | median
}

echo "archivo: ${FILE_MB}MB en $TMP - $RUNS corridas por medicion (mediana)"
echo

# ---- 1. baseline directa ------------------------------------------------------
DIRECT="$(runs_median curl_direct)" || fail "descarga directa"
echo "descarga directa (sin proxy):   $(mbs "$DIRECT") MB/s"

# ---- 2. a traves del proxy, una conexion ---------------------------------------
PROXIED="$(runs_median curl_proxied)" || fail "descarga via proxy"
echo "a traves del proxy (buf $DEFAULT_BUF):  $(mbs "$PROXIED") MB/s"
awk -v d="$DIRECT" -v p="$PROXIED" 'BEGIN {
    printf "relacion proxy/directo:         %.0f%%\n", p * 100 / d
    if (p > d * 0.9)
        print "aviso: proxy casi tan rapido como el directo -> el origen" \
              " (http.server de python) puede ser el cuello de botella;" \
              " interpretar el overhead con cautela"
}'
echo

# ---- 3. degradacion con N descargas paralelas ----------------------------------
echo "== paralelismo (N descargas simultaneas via proxy) =="
printf '%-6s %-14s %-18s %-12s\n' "N" "agregado MB/s" "por-conexion MB/s" "completadas"
for N in $PARALLEL_SET; do
    # cada descarga a su propio archivo y se espera PID por PID: hay que mirar el
    # status de cada curl, porque contar lineas de salida daria por completadas
    # las que fallaron (curl igual imprime su linea -w) y los ceros arrastrarian
    # el agregado y el por-conexion
    rm -f "$TMP"/par.*
    pids=""
    for i in $(seq "$N"); do
        curl_proxied >"$TMP/par.$i" &
        pids="$pids $!"
    done
    failed=0
    for pid in $pids; do
        wait "$pid" || failed=$((failed + 1))
    done
    speeds="$(cat "$TMP"/par.* 2>/dev/null)"
    done_n="$(echo "$speeds" | grep -c .)"
    if [ "$failed" -ne 0 ] || [ "$done_n" -ne "$N" ]; then
        fail "con N=$N completaron $done_n de $N ($failed con error)"
    fi
    echo "$speeds" | awk -v n="$N" '{ s += $1 } END {
        printf "%-6d %-14.1f %-18.1f %d/%d\n",
               n, s / 1048576, s / n / 1048576, NR, n }'
done
echo

# ---- 4. throughput segun buf_size (CONFIG en caliente) --------------------------
echo "== tamanio de buffer (CONFIG buf_size, sin reiniciar el server) =="
printf '%-10s %-12s %s\n' "buf_size" "MB/s" "corridas MB/s"
for size in $BUF_SIZES; do
    mgmt config buf_size "$size" >/dev/null \
        || fail "CONFIG buf_size $size rechazado"
    speeds="$(runs_speeds curl_proxied)" || fail "descarga con buf_size $size"
    med="$(echo "$speeds" | median)"
    all="$(echo "$speeds" | awk '{ printf "%.1f ", $1 / 1048576 }')"
    printf '%-10s %-12s %s\n' "$size" "$(mbs "$med")" "$all"
done
mgmt config buf_size "$DEFAULT_BUF" >/dev/null   # volver al default

echo
# los flags salen de Makefile.inc, no de una transcripcion a mano: interpretar
# numeros de throughput con los flags equivocados invalida toda la comparacion
echo "== metodologia (para el informe) =="
echo "  gcc:            $(gcc -dumpversion 2>/dev/null || echo '?')"
echo "  flags de build: $(sed -n 's/^COMPILER_FLAGS=//p' "$REPO/Makefile.inc")"
echo "  archivo:        ${FILE_MB}MB desde tmpfs - $RUNS corridas por medicion (mediana)"
echo "  falta anotar:   hardware (CPU/RAM) y entorno (WSL2 o Linux nativo)"
echo "OK"
exit 0

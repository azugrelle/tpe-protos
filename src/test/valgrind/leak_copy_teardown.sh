#!/bin/bash
#
# Prueba de fugas del teardown durante COPY (relay activo).
#
# Corre el server bajo valgrind, establece varias conexiones relayeadas contra
# un origen local (ver driver_copy.py) y le manda SIGTERM con el relay en pleno
# trabajo. En el shutdown, selector_destroy desregistra ambos fds de cada
# conexion -> handle_close -> socks5_destroy dos veces (references 2 -> 1 ->
# cleanup + pool). Si el refcount o la limpieza fallan, valgrind lo reporta.
#
# A diferencia del test de CONNECTING, el driver corre en background: tiene que
# seguir vivo al momento del SIGTERM (si cerrara sus sockets, las conexiones
# terminarian ordenadamente y no habria nada que teardownear).
#
# Sale con codigo != 0 si hay fugas, para poder usarlo en CI.
#
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
# helpers y entorno compartidos de los tests (PYTHONDONTWRITEBYTECODE)
. "$HERE/../lib.sh"
# puertos dinamicos que elige el kernel. Antes: el de SOCKS era fijo (leak_multiip
# y leak_shutdown compartian el 11093) y el de monitoreo ni se pasaba, asi que el
# server usaba su default 8080 -> con algo escuchando en 8080 (o con otra corrida
# en curso) el bind fallaba y el server salia con "el server no arranco".
PORT="$(free_port)"
MGMT_PORT="$(free_port)"
DRIVER="$HERE/driver_copy.py"
LOG="$(mktemp)"
VG=""
DRIVER_PID=""

cleanup() {
    [ -z "$DRIVER_PID" ] || kill "$DRIVER_PID" 2>/dev/null || true
    [ -z "$VG" ] || kill -TERM "$VG" 2>/dev/null || true
    rm -f "$LOG"
}
trap cleanup EXIT INT TERM

if ! command -v valgrind >/dev/null 2>&1; then
    echo "valgrind no esta instalado" >&2
    exit 2
fi

make -C "$REPO" server >/dev/null || { echo "fallo el build" >&2; exit 2; }

valgrind --leak-check=full --show-leak-kinds=definite,indirect \
         --errors-for-leak-kinds=definite,indirect --error-exitcode=99 \
         --track-fds=yes \
         --log-file="$LOG" \
         "$REPO/bin/server" -p "$PORT" -P "$MGMT_PORT" >/dev/null 2>&1 &
VG=$!

# esperar a que el server ESCUCHE, no solo a que el proceso viva: kill -0
# daba OK aunque el bind hubiera fallado, y el error recien aparecia despues,
# como un fallo del driver. El presupuesto es amplio porque bajo valgrind (y con
# varias corridas en paralelo) el arranque es lento; igual sale apenas escucha.
wait_listen "$VG" "$PORT" "el server bajo valgrind" 150 || exit 2
python3 "$DRIVER" "$PORT" &    # establece y SOSTIENE los relays (ver arriba)
DRIVER_PID=$!
sleep 3                        # deja que todas las conexiones lleguen a COPY
kill -0 "$DRIVER_PID" 2>/dev/null \
    || { wait "$DRIVER_PID"; echo "fallo el driver" >&2; exit 2; }
kill -TERM "$VG" 2>/dev/null   # SIGTERM -> selector_destroy -> cleanup
wait "$VG"
vg_status=$?
VG=""
wait "$DRIVER_PID" 2>/dev/null || true
DRIVER_PID=""

echo "===== resumen valgrind ====="
grep -E "FILE DESCRIPTORS|definitely lost|indirectly lost|no leaks are possible|ERROR SUMMARY" "$LOG"

# fuga = alguna linea "... lost: N bytes" con N != 0
leaks="$(grep -oE "(definitely|indirectly) lost: [0-9,]+ bytes" "$LOG" \
             | grep -vE ": 0 bytes")"
errors="$(grep -oE "ERROR SUMMARY: [0-9]+ errors" "$LOG" | grep -vE ": 0 errors")"
summary="$(grep -c "ERROR SUMMARY:" "$LOG")"

# con --error-exitcode=99, valgrind devuelve 99 SOLO si encontro errores; el
# resto es la salida normal del server (0: el SIGTERM drena y sale solo cuando
# el driver suelta los relays). Los FILE DESCRIPTORS del resumen son
# informativos aca: el que los audita como parte del veredicto es
# leak_shutdown_teardown.sh.
if [ "$vg_status" -ne 99 ] && [ "$summary" -eq 1 ] && [ -z "$leaks" ] \
   && [ -z "$errors" ]; then
    echo "OK: sin fugas"
    exit 0
fi
echo "FALLO: valgrind reporto errores/fugas" >&2
exit 1

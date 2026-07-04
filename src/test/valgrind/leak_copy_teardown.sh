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

PORT=11091
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
DRIVER="$HERE/driver_copy.py"
LOG="$(mktemp)"

if ! command -v valgrind >/dev/null 2>&1; then
    echo "valgrind no esta instalado" >&2
    exit 2
fi

make -C "$REPO" server >/dev/null || { echo "fallo el build" >&2; exit 2; }

valgrind --leak-check=full --show-leak-kinds=definite,indirect \
         --log-file="$LOG" \
         "$REPO/bin/server" -p "$PORT" >/dev/null 2>&1 &
VG=$!

sleep 5                        # valgrind arranca lento
python3 "$DRIVER" "$PORT" &    # establece y SOSTIENE los relays (ver arriba)
DRIVER_PID=$!
sleep 3                        # deja que todas las conexiones lleguen a COPY
kill -TERM "$VG" 2>/dev/null   # SIGTERM -> selector_destroy -> cleanup
wait "$VG"                     # el exit code mezcla fugas con la salida del
                               # server, el veredicto sale de parsear el log
wait "$DRIVER_PID" 2>/dev/null

echo "===== resumen valgrind ====="
grep -E "definitely lost|indirectly lost|no leaks are possible|ERROR SUMMARY" "$LOG"

# fuga = alguna linea "... lost: N bytes" con N != 0
leaks="$(grep -oE "(definitely|indirectly) lost: [0-9,]+ bytes" "$LOG" \
             | grep -vE ": 0 bytes")"
errors="$(grep -oE "ERROR SUMMARY: [0-9]+ errors" "$LOG" | grep -vE ": 0 errors")"
rm -f "$LOG"

if [ -z "$leaks" ] && [ -z "$errors" ]; then
    echo "OK: sin fugas"
    exit 0
fi
echo "FALLO: valgrind reporto errores/fugas" >&2
exit 1

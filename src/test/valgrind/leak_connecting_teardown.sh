#!/bin/bash
#
# Prueba de fugas del teardown durante CONNECTING.
#
# Corre el server bajo valgrind, deja varias conexiones colgadas en CONNECTING
# (ver driver_connecting.py) y le manda SIGTERM. En el shutdown, selector_destroy
# desregistra cada fd -> handle_close -> socks5_destroy, que debe liberar el
# origin_resolution de cada conexion antes de encolar en el pool. Si esa limpieza
# falta, valgrind reporta los addrinfo perdidos.
#
# Sale con codigo != 0 si hay fugas, para poder usarlo en CI.
#
set -u

PORT=11090
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
DRIVER="$HERE/driver_connecting.py"
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
         "$REPO/bin/server" -p "$PORT" >/dev/null 2>&1 &
VG=$!

sleep 5                      # valgrind arranca lento
kill -0 "$VG" 2>/dev/null || { echo "el server no arranco" >&2; exit 2; }
python3 "$DRIVER" "$PORT" &  # abre y sostiene las conexiones
DRIVER_PID=$!
sleep 1                      # asegura que el server esta en CONNECTING
kill -0 "$DRIVER_PID" 2>/dev/null \
    || { wait "$DRIVER_PID"; echo "fallo el driver" >&2; exit 2; }
kill -TERM "$VG" 2>/dev/null # SIGTERM -> selector_destroy -> cleanup
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
# resto es la salida normal del server (1 tras un SIGTERM). Los FILE
# DESCRIPTORS del resumen son informativos, no parte del veredicto: siempre
# figura el fd del --log-file de valgrind, y el teardown no cierra los fds de
# las conexiones aun vivas al SIGTERM (pendiente de robustez).
if [ "$vg_status" -ne 99 ] && [ "$summary" -eq 1 ] && [ -z "$leaks" ] \
   && [ -z "$errors" ]; then
    echo "OK: sin fugas"
    exit 0
fi
echo "FALLO: valgrind reporto errores/fugas" >&2
exit 1

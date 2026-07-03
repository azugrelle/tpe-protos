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

if ! command -v valgrind >/dev/null 2>&1; then
    echo "valgrind no esta instalado" >&2
    exit 2
fi

make -C "$REPO" server >/dev/null || { echo "fallo el build" >&2; exit 2; }

valgrind --leak-check=full --show-leak-kinds=definite,indirect \
         --log-file="$LOG" \
         "$REPO/bin/server" -p "$PORT" >/dev/null 2>&1 &
VG=$!

sleep 5                      # valgrind arranca lento
python3 "$DRIVER" "$PORT"    # abre y sostiene las conexiones
sleep 1                      # asegura que el server esta en CONNECTING
kill -TERM "$VG" 2>/dev/null # SIGTERM -> selector_destroy -> cleanup
wait "$VG"                   # el exit code mezcla fugas con la salida del server,
                             # asi que el veredicto sale de parsear el log

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

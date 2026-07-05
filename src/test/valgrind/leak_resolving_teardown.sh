#!/bin/bash
#
# Prueba de fugas y de la sincronización del apagado durante RESOLVING.
#
# Corre el server bajo valgrind con un shim que hace lento el getaddrinfo de
# los hosts "slow*" (slowdns_shim.c), llena el estado RESOLVING con el driver
# y manda SIGTERM con las resoluciones en vuelo. El apagado debe:
#   - esperar a los hilos de DNS (resolve_shutdown_wait) antes de destruir el
#     selector y las conexiones: si no, el hilo tardío escribe sobre memoria
#     liberada (invalid write) y notifica sobre un mutex destruido;
#   - liberar el addrinfo del hilo, la copia del selector_key y los jobs
#     embebidos sin despachar (los drena selector_destroy).
# Cualquiera de esas fallas aparece en el log como error o fuga.
#
# Sale con codigo != 0 si hay fugas/errores, para poder usarlo en CI.
#
set -u

PORT=11092
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
DRIVER="$HERE/driver_resolving.py"
LOG="$(mktemp)"
SHIM="$(mktemp --suffix=.so)"
VG=""
DRV=""

cleanup() {
    [ -z "$DRV" ] || kill "$DRV" 2>/dev/null || true
    [ -z "$VG" ] || kill -TERM "$VG" 2>/dev/null || true
    rm -f "$LOG" "$SHIM"
}
trap cleanup EXIT INT TERM

if ! command -v valgrind >/dev/null 2>&1; then
    echo "valgrind no esta instalado" >&2
    exit 2
fi

make -C "$REPO" server >/dev/null || { echo "fallo el build" >&2; exit 2; }
gcc -shared -fPIC -o "$SHIM" "$HERE/slowdns_shim.c" -ldl \
    || { echo "fallo el build del shim" >&2; exit 2; }

LD_PRELOAD="$SHIM" \
valgrind --leak-check=full --show-leak-kinds=definite,indirect \
         --errors-for-leak-kinds=definite,indirect --error-exitcode=99 \
         --track-fds=yes \
         --log-file="$LOG" \
         "$REPO/bin/server" -p "$PORT" >/dev/null 2>&1 &
VG=$!

sleep 5                        # valgrind arranca lento
kill -0 "$VG" 2>/dev/null || { echo "el server no arranco" >&2; exit 2; }
python3 "$DRIVER" "$PORT" &    # en background: sostiene las conexiones
DRV=$!
sleep 2                        # los REQUEST ya entraron; los "slow" siguen
                               # resolviendo (duermen 3s en el hilo)
kill -0 "$DRV" 2>/dev/null \
    || { wait "$DRV"; echo "fallo el driver" >&2; exit 2; }
kill -TERM "$VG" 2>/dev/null   # SIGTERM en plena resolucion
t0=$(date +%s%N)
wait "$VG"
vg_status=$?
t1=$(date +%s%N)
VG=""
shutdown_ms=$(( (t1 - t0) / 1000000 ))
kill "$DRV" 2>/dev/null
wait "$DRV" 2>/dev/null
DRV=""

echo "===== resumen valgrind ====="
grep -E "FILE DESCRIPTORS|definitely lost|indirectly lost|no leaks are possible|ERROR SUMMARY" "$LOG"
echo "SIGTERM -> exit: ${shutdown_ms} ms"

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
#
# El tiempo SIGTERM->exit valida resolve_shutdown_wait de forma deterministica:
# el SIGTERM cae con ~1s de resolucion pendiente, asi que un apagado correcto
# tarda al menos eso. Sin la espera, el proceso muere al instante y el hilo
# tardio ni llega a ejecutar su acceso invalido (valgrind no puede verlo), por
# eso el veredicto NO depende de cazar el use-after-free.
if [ "$vg_status" -ne 99 ] && [ "$summary" -eq 1 ] && [ -z "$leaks" ] \
   && [ -z "$errors" ] && [ "$shutdown_ms" -ge 500 ]; then
    echo "OK: sin fugas y el apagado espero a los hilos de DNS"
    exit 0
fi
echo "FALLO: valgrind reporto errores/fugas, o el apagado no espero" \
     "a las resoluciones en vuelo (SIGTERM->exit ${shutdown_ms} ms)" >&2
exit 1

#!/bin/bash
#
# Prueba de fugas del connect robusto multi-IP.
#
# Corre el server bajo valgrind con multiip_shim.so (los nombres magicos
# resuelven a varias direcciones de loopback, algunas caidas) y lo puebla con
# el driver: fallbacks que terminan conectando, agotamientos con REP 0x05 y
# clientes que cortan en el medio. El retry multiplica recursos por conexion
# (un fd por candidato probado, la lista de addrinfo viva entre intentos), asi
# que valgrind valida que:
#   - cada candidato fallido cerro SU fd (--track-fds);
#   - la lista de addrinfo se libera exactamente una vez por conexion, tambien
#     cuando el cliente corta antes del REPLY (socks5_cleanup);
#   - no hay accesos invalidos en el avance de candidatos.
#
# Sale con codigo != 0 si hay fugas/errores, para poder usarlo en CI.
#
set -u

PORT=11093
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
DRIVER="$HERE/driver_multiip.py"
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
gcc -shared -fPIC -o "$SHIM" "$REPO/src/test/integration/multiip_shim.c" -ldl \
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
sleep 2                        # retries y agotamientos ya corrieron (los
                               # rechazos de loopback son inmediatos)
kill -0 "$DRV" 2>/dev/null \
    || { wait "$DRV"; echo "fallo el driver" >&2; exit 2; }
kill -TERM "$VG" 2>/dev/null   # SIGTERM con conexiones vivas post-retry
wait "$VG"
vg_status=$?
VG=""
kill "$DRV" 2>/dev/null
wait "$DRV" 2>/dev/null
DRV=""

echo "===== resumen valgrind ====="
grep -E "FILE DESCRIPTORS|definitely lost|indirectly lost|no leaks are possible|ERROR SUMMARY" "$LOG"

# fuga = alguna linea "... lost: N bytes" con N != 0
leaks="$(grep -oE "(definitely|indirectly) lost: [0-9,]+ bytes" "$LOG" \
             | grep -vE ": 0 bytes")"
errors="$(grep -oE "ERROR SUMMARY: [0-9]+ errors" "$LOG" | grep -vE ": 0 errors")"
summary="$(grep -c "ERROR SUMMARY:" "$LOG")"

# con --error-exitcode=99, valgrind devuelve 99 SOLO si encontro errores; el
# resto es la salida normal del server (1 tras un SIGTERM). Los FILE
# DESCRIPTORS del resumen son informativos, no parte del veredicto (ver
# leak_resolving_teardown.sh). Las listas del shim tambien las audita
# valgrind: una resolucion sin liberar apareceria como definitely lost.
if [ "$vg_status" -ne 99 ] && [ "$summary" -eq 1 ] && [ -z "$leaks" ] \
   && [ -z "$errors" ]; then
    echo "OK: sin fugas ni errores en los caminos de retry multi-IP"
    exit 0
fi
echo "FALLO: valgrind reporto errores o fugas en el retry multi-IP" >&2
exit 1

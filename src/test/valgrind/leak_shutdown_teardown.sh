#!/bin/bash
#
# Prueba de fugas (memoria Y file descriptors) del apagado ordenado.
#
# Corre el server bajo valgrind con --track-fds y una mezcla de conexiones
# vivas (COPY con relay activo, un half-HELLO, una sesion de mgmt y una
# RESOLVING con el shim de DNS lento; ver driver_shutdown.py), y cubre los dos
# caminos de terminacion:
#
#   drain: 1 SIGTERM -> el server cierra pasivos y handshakes, espera a las
#          COPY (el driver las suelta a los segundos) y sale SOLO con exit 0.
#   force: 2 SIGTERM con las conexiones aun vivas -> corta ya y sale con 0.
#
# En ambos casos valgrind debe reportar cero fugas y, a diferencia de los
# otros leak_*, aca los FILE DESCRIPTORS si son parte del veredicto: el
# teardown cierra los fds de toda conexion viva, asi que al salir solo pueden
# quedar los std y el fd del --log-file de valgrind.
#
# Sale con codigo != 0 si hay fugas, fds abiertos de mas, o si el server no
# salio solo / no devolvio 0.
#
set -u

PORT=11093
MGMT_PORT=11094
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
DRIVER="$HERE/driver_shutdown.py"
SHIM="$(mktemp --suffix=.so)"
DRV_OUT="$(mktemp)"
LOG=""
VG=""
DRV=""

cleanup() {
    [ -z "$DRV" ] || kill "$DRV" 2>/dev/null || true
    [ -z "$VG" ] || kill -9 "$VG" 2>/dev/null || true
    rm -f "$SHIM" "$DRV_OUT" "${LOG:-}"
}
trap cleanup EXIT INT TERM

if ! command -v valgrind >/dev/null 2>&1; then
    echo "valgrind no esta instalado" >&2
    exit 2
fi

make -C "$REPO" server >/dev/null || { echo "fallo el build" >&2; exit 2; }
gcc -shared -fPIC -o "$SHIM" "$HERE/slowdns_shim.c" -ldl \
    || { echo "fallo el build del shim" >&2; exit 2; }

# espera a que el pid salga solo (sin mas señales); devuelve su exit code en
# WAIT_RC, o falla si sigue vivo pasado el limite
wait_exit() {
    local pid=$1 limit=$2
    for _ in $(seq 1 $((limit * 10))); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        return 1
    fi
    wait "$pid"
    WAIT_RC=$?
    return 0
}

# espera la linea de "ready" del driver en su salida (todo establecido, la
# ventana de RESOLVING recien abierta); falla si el driver murio antes
wait_ready() {
    for _ in $(seq 1 300); do
        grep -q "driver: .* modo " "$DRV_OUT" && return 0
        kill -0 "$DRV" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

# veredicto sobre el log de un caso: cero fugas, cero errores, y ningun fd
# abierto al salir mas alla de los std y el log de valgrind
check_log() {
    local log=$1 name=$2
    echo "===== resumen valgrind ($name) ====="
    grep -E "FILE DESCRIPTORS|definitely lost|indirectly lost|no leaks are possible|ERROR SUMMARY" "$log"

    local leaks errors fd_line open std
    leaks="$(grep -oE "(definitely|indirectly) lost: [0-9,]+ bytes" "$log" \
                 | grep -vE ": 0 bytes")"
    errors="$(grep -oE "ERROR SUMMARY: [0-9]+ errors" "$log" | grep -vE ": 0 errors")"
    if [ -n "$leaks" ] || [ -n "$errors" ]; then
        echo "FALLO ($name): valgrind reporto fugas/errores" >&2
        return 1
    fi
    # "FILE DESCRIPTORS: N open (M std) at exit": N-M debe ser <= 1 (el log de
    # valgrind). Si el formato no aparece (valgrind viejo), fallar explicito en
    # vez de dar un veredicto vacio.
    fd_line="$(grep -oE "FILE DESCRIPTORS: [0-9]+ open \([0-9]+ std\)" "$log" | head -1)"
    if [ -z "$fd_line" ]; then
        echo "FALLO ($name): no encontre 'FILE DESCRIPTORS: N open (M std)' en el log" >&2
        echo "  (¿valgrind sin ese formato de --track-fds? se necesita para el veredicto)" >&2
        return 1
    fi
    open="$(echo "$fd_line" | grep -oE "[0-9]+" | sed -n 1p)"
    std="$(echo "$fd_line"  | grep -oE "[0-9]+" | sed -n 2p)"
    if [ $((open - std)) -gt 1 ]; then
        echo "FALLO ($name): quedaron fds abiertos al salir (open-std=$((open - std)))" >&2
        return 1
    fi
    return 0
}

start_server() {
    LOG="$(mktemp)"
    LD_PRELOAD="$SHIM" \
    valgrind --leak-check=full --show-leak-kinds=definite,indirect \
             --errors-for-leak-kinds=definite,indirect --error-exitcode=99 \
             --track-fds=yes \
             --log-file="$LOG" \
             "$REPO/bin/server" -p "$PORT" -P "$MGMT_PORT" >/dev/null 2>&1 &
    VG=$!
    sleep 5                    # valgrind arranca lento
    kill -0 "$VG" 2>/dev/null || { echo "el server no arranco" >&2; exit 2; }
}

# ---- caso 1: drenado (1 señal, el server sale solo) -------------------------
start_server
LOG_DRAIN="$LOG"

: > "$DRV_OUT"
python3 "$DRIVER" "$PORT" "$MGMT_PORT" drain > "$DRV_OUT" 2>&1 &
DRV=$!
# esperar el "ready" (todo establecido; la ventana de 3s de la RESOLVING
# recien abre) y señalar enseguida, adentro de la ventana
wait_ready || { cat "$DRV_OUT" >&2; echo "fallo el driver (drain)" >&2; exit 2; }
sleep 0.5

kill -TERM "$VG" 2>/dev/null
# el driver suelta las COPY solo; el server debe salir sin mas ayuda
if ! wait_exit "$VG" 30; then
    echo "FALLO (drain): el server no salio solo tras el drenado" >&2
    exit 1
fi
VG=""
[ "$WAIT_RC" -eq 0 ] || { echo "FALLO (drain): exit $WAIT_RC (esperaba 0)" >&2; exit 1; }
wait "$DRV" 2>/dev/null || true
DRV=""
check_log "$LOG_DRAIN" drain || exit 1
rm -f "$LOG_DRAIN"
echo "drain: salio solo con exit 0 y sin fugas ni fds"

# ---- caso 2: corte forzado (2 señales con todo vivo) ------------------------
start_server
LOG_FORCE="$LOG"

: > "$DRV_OUT"
python3 "$DRIVER" "$PORT" "$MGMT_PORT" force > "$DRV_OUT" 2>&1 &
DRV=$!
wait_ready || { cat "$DRV_OUT" >&2; echo "fallo el driver (force)" >&2; exit 2; }

# ambas señales adentro de la ventana de 3s de la RESOLVING: la 2ª cae con el
# getaddrinfo aun en vuelo, asi el finally espera al worker y selector_destroy
# drena el job de notificacion pendiente antes de liberar la conexion
sleep 0.5
kill -TERM "$VG" 2>/dev/null   # entra en drenado: COPY y mgmt siguen vivas
sleep 1
kill -TERM "$VG" 2>/dev/null   # corte forzado
if ! wait_exit "$VG" 20; then
    echo "FALLO (force): el server no salio tras la 2da señal" >&2
    exit 1
fi
VG=""
[ "$WAIT_RC" -eq 0 ] || { echo "FALLO (force): exit $WAIT_RC (esperaba 0)" >&2; exit 1; }
kill "$DRV" 2>/dev/null || true
wait "$DRV" 2>/dev/null || true
DRV=""
check_log "$LOG_FORCE" force || exit 1
rm -f "$LOG_FORCE"
echo "force: la 2da señal corto con exit 0 y sin fugas ni fds"

echo "OK: apagado sin fugas en ambos caminos"
exit 0

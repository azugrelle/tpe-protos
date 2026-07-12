#!/bin/bash
#
# Prueba de estres: conexiones concurrentes.
#
# Abre TARGET tuneles SOCKS5 autenticados sostenidos (concurrent_tunnels.py,
# un solo proceso) contra un origen local que los mantiene vivos
# (hold_server.py), y con los tuneles abiertos:
#   1. contrasta el conteo contra CONNECTIONS del monitoreo,
#   2. sigue abriendo de a uno hasta el primer rechazo, para medir el techo
#      real (el teorico es MAX_CONNECTIONS=511, acotado por FD_SETSIZE),
#   3. verifica que el rechazo sea limpio (TCP aceptado y cerrado sin reply
#      SOCKS) y que el server siga sirviendo trafico por los tuneles vivos,
#   4. cierra tuneles y verifica que se vuelvan a aceptar conexiones.
#
# Variables: TARGET (default 500, el minimo de la consigna).
#
# La salida final es un resumen listo para pegar en el informe.
# Sale 0 si todo ok, 1 si una verificacion fallo, 2 si falta una dependencia
# o fallo el build.
#
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
. "$HERE/../lib.sh"
TARGET="${TARGET:-500}"
ADMIN="admin:secreto"
PROXY_USER="alice"
PROXY_PASS="pass1"

command -v python3 >/dev/null 2>&1 || { echo "falta python3" >&2; exit 2; }

# cada tunel usa 2 fds en el server y 1 en el cliente python; el limite de
# fds del shell se hereda a ambos.
# `ulimit -n` puede devolver la cadena "unlimited", que no compara numericamente:
# [ abortaria con "integer expression expected" y el if quedaria falso, salteando
# en silencio el chequeo que justamente tiene que abortar.
NEEDED_NOFILE=$((TARGET * 2 + 100))
NOFILE="$(ulimit -n)"
if [ "$NOFILE" != "unlimited" ] && [ "$NOFILE" -lt "$NEEDED_NOFILE" ]; then
    echo "ulimit -n muy bajo ($NOFILE) para $TARGET tuneles: correr" >&2
    echo "  ulimit -n $NEEDED_NOFILE antes de esta prueba" >&2
    exit 2
fi

make -C "$REPO" server client >/dev/null || { echo "fallo el build" >&2; exit 2; }

TMP="$(mktemp -d)"
PROXY_PID=""
HOLD_PID=""
TUN_PID=""
cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
    [ -n "$HOLD_PID" ]  && kill "$HOLD_PID"  2>/dev/null
    [ -n "${TUN_PID:-}" ] && kill "${TUN_PID}" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# Escribirle al coproceso de tuneles despues de que murio puede entregar SIGPIPE;
# con la disposicion default el shell moriria con 141 salteando el trap EXIT y
# dejando huerfanos a bin/server y hold_server.py. Con un handler el shell
# sobrevive y la escritura devuelve EPIPE, que ask() reporta como fail().
# Es un handler (':') y no 'trap "" PIPE' porque las senales *ignoradas* se heredan
# ignoradas por los hijos --le cambiaria la disposicion de SIGPIPE al server que
# esta bajo prueba--, mientras que las *atrapadas* se resetean a default en ellos.
trap ':' PIPE

PROXY_PORT="$(free_port)"
MGMT_PORT="$(free_port)"
HOLD_PORT="$(free_port)"

python3 "$HERE/hold_server.py" "$HOLD_PORT" &
HOLD_PID=$!
# fail() (lib.sh) muestra el tail de SERVER_LOG para diagnosticar
SERVER_LOG="$TMP/server.log"
"$REPO/bin/server" -p "$PROXY_PORT" -P "$MGMT_PORT" \
    -a "$ADMIN" -u "$PROXY_USER:$PROXY_PASS" \
    >"$SERVER_LOG" 2>&1 &
PROXY_PID=$!

wait_listen "$HOLD_PID"  "$HOLD_PORT"  "hold_server" || exit 2
wait_listen "$PROXY_PID" "$PROXY_PORT" "proxy"       || exit 2
wait_listen "$PROXY_PID" "$MGMT_PORT"  "monitoreo"   || exit 2

# los tuneles quedan ociosos mucho rato: que el timeout de inactividad
# (default 300s) no los cierre en el medio de la prueba
mgmt config timeout 3600 >/dev/null || fail "no se pudo subir el timeout"

# ---- 1. abrir TARGET tuneles sostenidos -------------------------------------
echo "abriendo $TARGET tuneles (esto tarda unos segundos)..."
coproc TUN {
    python3 "$HERE/concurrent_tunnels.py" "$PROXY_PORT" \
        "$PROXY_USER" "$PROXY_PASS" 127.0.0.1 "$HOLD_PORT" "$TARGET"
}

# Cuando el coproceso muere, bash cierra sus fds y borra TUN[]/TUN_PID: escribir a
# un ${TUN[1]} sin definir seria un criptico "unbound variable" (set -u), y si todavia
# no lo reapeo, el fd sigue abierto sin lector. Chequear antes deja reportar la causa
# real --murio el cliente de tuneles-- en vez de culpar al server por no responder.
tun_alive() {
    [ -n "${TUN_PID:-}" ] && [ -n "${TUN[1]:-}" ] && kill -0 "$TUN_PID" 2>/dev/null
}

# ask() NO puede abortar por su cuenta: se la invoca dentro de $(...), donde un
# exit solo mata al subshell y el script seguiria con una respuesta vacia. Peor,
# si el read vencio por timeout la respuesta tardia queda en el pipe y la consume
# el ask SIGUIENTE, corriendo un lugar todos los pares pregunta/respuesta. Por eso
# devuelve status y el caller aborta con fail(): al cortar en el primer fallo, el
# pipe desincronizado nunca se llega a leer.
ask() {  # manda un comando al proceso de tuneles y devuelve su respuesta
    if ! tun_alive; then
        echo "el cliente de tuneles murio antes de poder mandarle '$1'" >&2
        return 1
    fi
    if ! echo "$1" >&"${TUN[1]}" 2>/dev/null; then
        echo "no se pudo mandar '$1' al cliente de tuneles (murio en el medio?)" >&2
        return 1
    fi
    local resp
    if ! read -t 60 -u "${TUN[0]}" resp; then
        echo "sin respuesta del cliente de tuneles a '$1' (timeout o murio)" >&2
        return 1
    fi
    echo "$resp"
}

read -t 300 -u "${TUN[0]}" opened || fail "la fase de apertura no respondio"
case "$opened" in
    UP*)        NUP="${opened#UP }" ;;
    OPEN_FAIL*) fail "solo se abrieron $(echo "$opened" | cut -d' ' -f2) de $TARGET tuneles ($(echo "$opened" | cut -d' ' -f3))" ;;
    *)          fail "respuesta inesperada de la apertura: $opened" ;;
esac
echo "tuneles abiertos: $NUP"

# ---- 2. contrastar con el monitoreo -----------------------------------------
CURRENT="$(mgmt connections | awk '$1 == "current_connections:" {print $2}')"
[ "$CURRENT" = "$NUP" ] \
    || fail "CONNECTIONS reporta $CURRENT conexiones y hay $NUP tuneles"
echo "el monitoreo confirma $CURRENT conexiones concurrentes"

# ---- 3. buscar el techo real -------------------------------------------------
# desde TARGET, seguir abriendo hasta el primer rechazo (con una cota por si
# el tope no aparece donde se espera)
CEILING="$NUP"
SYMPTOM=""
for _ in $(seq 1 40); do
    resp="$(ask probe)" || fail "no se pudo sondear con $CEILING tuneles abiertos"
    case "$resp" in
        "PROBE UP")        CEILING=$((CEILING + 1)) ;;
        PROBE\ REJECTED*)  SYMPTOM="${resp#PROBE REJECTED }"; break ;;
        *)                 fail "respuesta inesperada al probe: $resp" ;;
    esac
done
if [ -z "$SYMPTOM" ]; then
    echo "aviso: no se alcanzo el tope tras $CEILING tuneles (subir la cota de probes)"
else
    echo "techo alcanzado: $CEILING tuneles; el siguiente fue rechazado ($SYMPTOM)"
fi

# ---- 4. el server sigue vivo saturado ----------------------------------------
resp="$(ask echo)" || fail "no se pudo pedir un eco con el server saturado"
[ "$resp" = "ECHO OK" ] || fail "eco por un tunel vivo con el server saturado: $resp"
echo "el server sigue relayando trafico por los tuneles vivos"

# ---- 5. cerrar libera cupo ----------------------------------------------------
resp="$(ask "close 10")" || fail "no se pudieron cerrar 10 tuneles"
case "$resp" in
    "CLOSED 10 "*) ;;
    *)             fail "respuesta inesperada al cerrar 10 tuneles: $resp" ;;
esac
sleep 0.5   # dar tiempo a que el server procese los cierres
resp="$(ask probe)" || fail "no se pudo sondear tras cerrar 10 tuneles"
[ "$resp" = "PROBE UP" ] || fail "tras cerrar 10 tuneles no se acepto uno nuevo: $resp"
echo "tras cerrar tuneles se vuelven a aceptar conexiones"

MAXC="$(mgmt connections | awk '$1 == "max_concurrent:" {print $2}')"

if tun_alive; then
    echo "quit" >&"${TUN[1]}" 2>/dev/null
    wait "$TUN_PID" 2>/dev/null
fi

# ---- resumen -------------------------------------------------------------------
echo
echo "== resumen (para el informe) =="
echo "  tuneles concurrentes sostenidos:  $NUP (objetivo: $TARGET)"
echo "  techo medido:                     $CEILING (teorico: 511)"
echo "  sintoma al saturar:               ${SYMPTOM:-no alcanzado}"
echo "  max_concurrent segun el server:   $MAXC"
if [ -n "$SYMPTOM" ]; then
    echo "  comportamiento saturado:          sigue relayando; rechazo limpio"
else
    echo "  comportamiento saturado:          no evaluado (no se llego al tope)"
fi
echo "OK"
exit 0

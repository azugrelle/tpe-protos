#!/bin/bash
#
# Prueba end-to-end del cliente de monitoreo contra el server real.
#
# Cubre cuatro escenarios:
#   1. sesion completa via one-shot: stats, users, connections, config (valido
#      e invalido) y el contrato de exit codes (0 = +OK, 1 = -ERR o login
#      fallido, 2 = uso invalido local, que ademas no toca la red).
#   2. REPL scripteado por stdin: multi-comando, un comando desconocido no
#      corta la sesion, el quit final devuelve 0, los prompts van a stderr
#      (stdout queda solo con respuestas) y el password nunca se re-imprime.
#   3. metricas con trafico real: un tunel SOCKS autenticado hacia un eco
#      local debe reflejarse en STATS/USERS/CONNECTIONS mientras vive y
#      desaparecer al cerrarse. Valida VALORES, no solo framing: los
#      escenarios anteriores pasan igual con contadores siempre en cero.
#   4. caida del server a mitad de sesion: coordinado con un FIFO para matar
#      el server ENTRE dos comandos; el cliente debe reportar la desconexion
#      con un mensaje claro y exit exactamente 1 (un crash saldria >= 128).
#
# Sale 0 si todo ok, 1 si una asercion fallo, 2 si falta una dependencia o
# fallo el build.
#
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"

ADMIN_USER=admin
ADMIN_PASS=secret
SOCKS_USER=testuser
SOCKS_PASS=testpass

command -v python3 >/dev/null 2>&1 || { echo "falta python3" >&2; exit 2; }

# siempre contra los binarios recien compilados
make -C "$REPO" server client >/dev/null || { echo "fallo el build" >&2; exit 2; }

TMP="$(mktemp -d)"
SERVER_PID=""
CLIENT_PID=""
ECHO_PID=""
TUNNEL_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null
    [ -n "$ECHO_PID" ]   && kill "$ECHO_PID"   2>/dev/null
    [ -n "$TUNNEL_PID" ] && kill "$TUNNEL_PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# puertos dinamicos (los elige el kernel) para no colisionar entre corridas
free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0));
print(s.getsockname()[1]); s.close()'
}
PROXY_PORT="$(free_port)"
MNG_PORT="$(free_port)"

"$REPO/bin/server" -p "$PROXY_PORT" -L 127.0.0.1 -P "$MNG_PORT" \
                   -a "$ADMIN_USER:$ADMIN_PASS" \
                   -u "$SOCKS_USER:$SOCKS_PASS" >/dev/null 2>&1 &
SERVER_PID=$!

# esperar a que el server escuche de verdad (y detectar si murio al nacer)
wait_listen() {
    local pid=$1 port=$2 name=$3
    for _ in $(seq 1 50); do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "$name no arranco" >&2
            return 1
        fi
        if python3 -c "import socket,sys
s = socket.socket(); s.settimeout(0.2)
try: s.connect((\"127.0.0.1\", $port))
except OSError: sys.exit(1)"; then
            return 0
        fi
        sleep 0.1
    done
    echo "$name no escucha en el puerto $port" >&2
    return 1
}
wait_listen "$SERVER_PID" "$MNG_PORT" "monitoreo" || exit 2

# corre el cliente en one-shot y deja stdout en OUT, stderr en $TMP/err, y el
# exit code en RC
oneshot() {
    OUT="$("$REPO/bin/client" -L 127.0.0.1 -P "$MNG_PORT" "$@" \
           2>"$TMP/err.txt")"
    RC=$?
}

# ---- 1. sesion completa via one-shot ----------------------------------------

oneshot -a "$ADMIN_USER:$ADMIN_PASS" stats
if [ "$RC" -ne 0 ] || ! grep -q "uptime:" <<<"$OUT"; then
    echo "FALLO: stats one-shot: exit $RC, salida: $OUT" >&2
    exit 1
fi

oneshot -a "$ADMIN_USER:$ADMIN_PASS" users
if [ "$RC" -ne 0 ] || ! grep -q "active users" <<<"$OUT"; then
    echo "FALLO: users one-shot: exit $RC, salida: $OUT" >&2
    exit 1
fi

oneshot -a "$ADMIN_USER:$ADMIN_PASS" connections
if [ "$RC" -ne 0 ] || ! grep -q "current_connections:" <<<"$OUT"; then
    echo "FALLO: connections one-shot: exit $RC, salida: $OUT" >&2
    exit 1
fi

oneshot -a "$ADMIN_USER:$ADMIN_PASS" config timeout 30
if [ "$RC" -ne 0 ] || [ "$OUT" != "+OK" ]; then
    echo "FALLO: config timeout 30: exit $RC, salida: $OUT" >&2
    exit 1
fi

oneshot -a "$ADMIN_USER:$ADMIN_PASS" config timeout abc
if [ "$RC" -ne 1 ]; then
    echo "FALLO: config invalido debia salir 1, salio $RC" >&2
    exit 1
fi

oneshot -a "$ADMIN_USER:bad" stats
if [ "$RC" -ne 1 ] || [ -n "$OUT" ]; then
    echo "FALLO: login invalido debia salir 1 con stdout vacio (exit $RC)" >&2
    exit 1
fi

echo "one-shot: sesion completa con los exit codes esperados"

# ---- 2. uso invalido local: exit 2 y sin tocar la red ------------------------

# contra un puerto sin nadie escuchando: si el cliente intentara conectar
# antes de validar, el error seria de conexion (exit 1), no de uso (exit 2)
DEAD_PORT="$(free_port)"
for args in "stats extra" "foo"; do
    # shellcheck disable=SC2086  # la separacion en palabras es deliberada
    "$REPO/bin/client" -L 127.0.0.1 -P "$DEAD_PORT" $args \
        >/dev/null 2>&1
    rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "FALLO: '$args' debia salir 2 sin conectar, salio $rc" >&2
        exit 1
    fi
done

echo "uso invalido: exit 2 sin tocar la red"

# ---- 3. REPL scripteado por stdin --------------------------------------------

printf '%s\n%s\nstats\nfoo\nquit\n' "$ADMIN_USER" "$ADMIN_PASS" \
    | "$REPO/bin/client" -L 127.0.0.1 -P "$MNG_PORT" \
      >"$TMP/repl_out.txt" 2>"$TMP/repl_err.txt"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "FALLO: la sesion REPL debia salir 0, salio $rc" >&2
    exit 1
fi
if ! grep -q "uptime:" "$TMP/repl_out.txt" \
   || ! grep -q "+OK bye" "$TMP/repl_out.txt"; then
    echo "FALLO: falta la respuesta de stats o el bye en el stdout del REPL" >&2
    exit 1
fi
if ! grep -q "unknown command 'foo'" "$TMP/repl_err.txt"; then
    echo "FALLO: el comando desconocido no se reporto por stderr" >&2
    exit 1
fi
if grep -q "$ADMIN_PASS" "$TMP/repl_out.txt" "$TMP/repl_err.txt"; then
    echo "FALLO: el password aparece re-impreso en la salida" >&2
    exit 1
fi

echo "REPL: sesion multi-comando, errores locales sin cortar, password nunca impreso"

# ---- 4. metricas con trafico SOCKS real ---------------------------------------

# hasta aca solo hubo sesiones de monitoreo, que no cuentan como conexiones
# del proxy: stats/users/connections respondieron bien formados pero con todo
# en cero. Un tunel SOCKS autenticado contra un eco local permite asertar los
# valores: alta mientras el tunel vive, baja al cerrarse.

ECHO_PORT="$(free_port)"
python3 -c '
import socket, sys
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(4)
while True:
    c, _ = srv.accept()
    while True:
        d = c.recv(4096)
        if not d:
            break
        c.sendall(d)
    c.close()
' "$ECHO_PORT" >/dev/null 2>&1 &
ECHO_PID=$!
wait_listen "$ECHO_PID" "$ECHO_PORT" "eco" || exit 2

# el FIFO sostiene el tunel abierto mientras se consultan las metricas y
# permite soltarlo en el momento exacto (mismo patron que el escenario 5)
mkfifo "$TMP/tunnel_fifo"
exec 4<>"$TMP/tunnel_fifo"
python3 "$HERE/authed_tunnel_client.py" "$PROXY_PORT" \
    "$SOCKS_USER" "$SOCKS_PASS" 127.0.0.1 "$ECHO_PORT" <"$TMP/tunnel_fifo" \
    >"$TMP/tunnel_out.txt" 2>"$TMP/tunnel_err.txt" &
TUNNEL_PID=$!

# TUNNEL_UP aparece recien despues del eco: ya hay bytes relayados que asertar
ok=0
for _ in $(seq 1 50); do
    if grep -q "TUNNEL_UP" "$TMP/tunnel_out.txt" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.1
done
if [ "$ok" -ne 1 ]; then
    echo "FALLO: el tunel SOCKS autenticado no se establecio" >&2
    cat "$TMP/tunnel_err.txt" >&2
    exit 1
fi

# el cliente alinea las columnas: entre el campo y el valor hay 1+ espacios
oneshot -a "$ADMIN_USER:$ADMIN_PASS" stats
if [ "$RC" -ne 0 ] \
   || ! grep -Eq "historical_connections: +[1-9]" <<<"$OUT" \
   || ! grep -Eq "concurrent_connections: +[1-9]" <<<"$OUT" \
   || ! grep -Eq "active_users: +[1-9]" <<<"$OUT" \
   || ! grep -Eq "bytes_transferred: +[1-9]" <<<"$OUT"; then
    echo "FALLO: stats no refleja el tunel abierto: $OUT" >&2
    exit 1
fi

oneshot -a "$ADMIN_USER:$ADMIN_PASS" users
if [ "$RC" -ne 0 ] || ! grep -q "$SOCKS_USER" <<<"$OUT"; then
    echo "FALLO: users no lista a $SOCKS_USER con su tunel abierto: $OUT" >&2
    exit 1
fi

oneshot -a "$ADMIN_USER:$ADMIN_PASS" connections
if [ "$RC" -ne 0 ] || ! grep -Eq "current_connections: +[1-9]" <<<"$OUT"; then
    echo "FALLO: connections no refleja el tunel abierto: $OUT" >&2
    exit 1
fi

# soltar el tunel y verificar la baja (el teardown es asincronico: se sondea)
printf '\n' >&4
exec 4>&-
for _ in $(seq 1 50); do
    kill -0 "$TUNNEL_PID" 2>/dev/null || break
    sleep 0.1
done
if kill -0 "$TUNNEL_PID" 2>/dev/null; then
    echo "FALLO: el cliente del tunel no salio tras soltar su stdin" >&2
    exit 1
fi
wait "$TUNNEL_PID"
rc=$?
TUNNEL_PID=""
if [ "$rc" -ne 0 ]; then
    echo "FALLO: el tunel SOCKS fallo (exit $rc)" >&2
    cat "$TMP/tunnel_err.txt" >&2
    exit 1
fi

ok=0
for _ in $(seq 1 50); do
    oneshot -a "$ADMIN_USER:$ADMIN_PASS" users
    if [ "$RC" -eq 0 ] && ! grep -q "$SOCKS_USER" <<<"$OUT"; then
        oneshot -a "$ADMIN_USER:$ADMIN_PASS" connections
        if [ "$RC" -eq 0 ] && grep -Eq "current_connections: +0$" <<<"$OUT"; then
            ok=1
            break
        fi
    fi
    sleep 0.1
done
if [ "$ok" -ne 1 ]; then
    echo "FALLO: la baja del tunel no se reflejo en users/connections" >&2
    exit 1
fi

kill "$ECHO_PID" 2>/dev/null
ECHO_PID=""

echo "metricas: stats/users/connections reflejan el tunel real, alta y baja"

# ---- 5. caida del server entre dos comandos ----------------------------------

# el FIFO permite matar el server ENTRE dos comandos: un heredoc entregaria
# todo el input de una y no habria forma de coordinar el momento del kill. La
# apertura <> no bloquea (solo-escritura esperaria un lector que todavia no
# existe, porque el cliente se lanza despues).
mkfifo "$TMP/fifo"
exec 3<>"$TMP/fifo"
"$REPO/bin/client" -L 127.0.0.1 -P "$MNG_PORT" <"$TMP/fifo" \
    >"$TMP/kill_out.txt" 2>"$TMP/kill_err.txt" &
CLIENT_PID=$!

printf '%s\n%s\nstats\n' "$ADMIN_USER" "$ADMIN_PASS" >&3

# esperar la respuesta completa del stats (uptime es su ultimo campo; el
# cliente hace flush por respuesta, asi que aparece apenas termina)
ok=0
for _ in $(seq 1 50); do
    if grep -q "uptime:" "$TMP/kill_out.txt" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.1
done
if [ "$ok" -ne 1 ]; then
    echo "FALLO: el stats previo al kill no respondio" >&2
    exit 1
fi

kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null
SERVER_PID=""

printf 'users\n' >&3

# el cliente debe morir solo (con mensaje), no colgarse ni crashear
for _ in $(seq 1 100); do
    kill -0 "$CLIENT_PID" 2>/dev/null || break
    sleep 0.1
done
if kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "FALLO: el cliente no salio tras la caida del server" >&2
    exit 1
fi
wait "$CLIENT_PID"
rc=$?
CLIENT_PID=""
exec 3>&-

# exactamente 1: un exit >= 128 seria una señal (crash), 0 seria mentir
if [ "$rc" -ne 1 ]; then
    echo "FALLO: la desconexion debia salir 1, salio $rc" >&2
    exit 1
fi
# el mensaje depende de a quien le pego primero el cierre (recv o send)
if ! grep -Eq "server closed the connection|recv: |send: " "$TMP/kill_err.txt"; then
    echo "FALLO: no hay mensaje claro de desconexion en stderr" >&2
    cat "$TMP/kill_err.txt" >&2
    exit 1
fi

echo "caida del server: mensaje claro y exit 1, sin crash"

echo "OK: cliente de monitoreo y metricas integros en todos los escenarios"
exit 0

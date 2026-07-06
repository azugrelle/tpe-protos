#!/bin/bash
#
# Prueba end-to-end de la config dinamica en caliente (T72).
#
# Cubre los dos parametros contra el MISMO proceso, sin reiniciar en ningun
# momento:
#   1. timeout: CONFIG timeout bajo + una conexion muda al proxy -> el server
#      la cierra sola dentro de la ventana; CONFIG timeout alto -> una
#      conexion nueva sobrevive esa misma ventana (aplica a TODAS las vivas,
#      se lee en cada pasada del barrido).
#   2. buf_size: una transferencia grande en curso + CONFIG buf_size distinto
#      a mitad de camino -> la transferencia viva termina integra (aplica
#      solo a conexiones nuevas) y una transferencia nueva post-cambio
#      tambien llega integra.
#
# Sale 0 si todo ok, 1 si alguna asercion fallo, 2 si falta una dependencia o
# fallo el build.
#
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"

ADMIN_USER=admin
ADMIN_PASS=secret
SIZE_MB=5
RATE=1M            # ~5s de transferencia: ventana comoda para el CONFIG
XFER_TIMEOUT=60

for dep in curl python3 sha256sum; do
    command -v "$dep" >/dev/null 2>&1 || { echo "falta $dep" >&2; exit 2; }
done

make -C "$REPO" server client >/dev/null || { echo "fallo el build" >&2; exit 2; }

TMP="$(mktemp -d)"
SERVER_PID=""
HTTP_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null
    [ -n "$HTTP_PID" ]   && kill "$HTTP_PID"      2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0));
print(s.getsockname()[1]); s.close()'
}

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

# corre el cliente de monitoreo en one-shot; deja stdout en OUT y el exit
# code en RC (patron de monitor_session.sh)
oneshot() {
    OUT="$("$REPO/bin/client" -L 127.0.0.1 -P "$MNG_PORT" \
           -a "$ADMIN_USER:$ADMIN_PASS" "$@" 2>"$TMP/err.txt")"
    RC=$?
}

# se conecta al proxy y bloquea en recv(1) hasta que el server cierre (EOF) o
# venza el timeout local. Imprime el tiempo transcurrido y sale 0 si cerro,
# 1 si seguia abierta al vencer el timeout, 2 ante dato inesperado.
idle_wait_close() {
    local port=$1 local_timeout=$2
    python3 - "$port" "$local_timeout" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
local_timeout = float(sys.argv[2])
s = socket.socket()
s.settimeout(local_timeout)
s.connect(("127.0.0.1", port))
start = time.time()
try:
    data = s.recv(1)
except socket.timeout:
    sys.exit(1)
elapsed = time.time() - start
if data == b"":
    print(f"{elapsed:.1f}")
    sys.exit(0)
sys.exit(2)
PY
}

HTTP_PORT="$(free_port)"
PROXY_PORT="$(free_port)"
MNG_PORT="$(free_port)"

dd if=/dev/urandom of="$TMP/big.bin" bs=1M count="$SIZE_MB" status=none
want="$(sha256sum "$TMP/big.bin" | cut -d' ' -f1)"

python3 -m http.server "$HTTP_PORT" --directory "$TMP" >/dev/null 2>&1 &
HTTP_PID=$!
wait_listen "$HTTP_PID" "$HTTP_PORT" "http.server" || exit 2

"$REPO/bin/server" -p "$PROXY_PORT" -L 127.0.0.1 -P "$MNG_PORT" \
                   -a "$ADMIN_USER:$ADMIN_PASS" >/dev/null 2>&1 &
SERVER_PID=$!
wait_listen "$SERVER_PID" "$PROXY_PORT" "proxy" || exit 2
wait_listen "$SERVER_PID" "$MNG_PORT"   "monitoreo" || exit 2

# ---- 1. timeout: aplica a TODAS las conexiones, sin reiniciar --------------

oneshot config timeout 3
if [ "$RC" -ne 0 ] || [ "$OUT" != "+OK" ]; then
    echo "FALLO: config timeout 3: exit $RC, salida: $OUT" >&2
    exit 1
fi

# ventana generosa (timeout + margen del barrido de 1s + margen de red)
elapsed="$(idle_wait_close "$PROXY_PORT" 8)"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "FALLO: la conexion muda no se cerro dentro de la ventana (rc=$rc)" >&2
    exit 1
fi
echo "timeout: conexion inactiva cerrada a los ${elapsed}s (config timeout 3)"

oneshot config timeout 30
if [ "$RC" -ne 0 ] || [ "$OUT" != "+OK" ]; then
    echo "FALLO: config timeout 30: exit $RC, salida: $OUT" >&2
    exit 1
fi

# una conexion NUEVA, sin reiniciar el proceso, tiene que sobrevivir mas de
# lo que aguantaba con el timeout viejo (3s) -- si no cambio nada, cerraria
# antes de este chequeo
idle_wait_close "$PROXY_PORT" 6
rc=$?
if [ "$rc" -eq 0 ]; then
    echo "FALLO: la conexion se cerro pese a haber subido el timeout" >&2
    exit 1
elif [ "$rc" -ne 1 ]; then
    echo "FALLO: comportamiento inesperado esperando el cierre (rc=$rc)" >&2
    exit 1
fi
echo "timeout: subir el valor en caliente evita el cierre temprano, sin reiniciar"

# ---- 2. buf_size: aplica solo a conexiones nuevas --------------------------

curl -s --max-time "$XFER_TIMEOUT" --limit-rate "$RATE" \
     --socks5-hostname "127.0.0.1:$PROXY_PORT" \
     "http://127.0.0.1:$HTTP_PORT/big.bin" -o "$TMP/got_live.bin" &
CURL_PID=$!

sleep 1   # a esta velocidad la transferencia recien empieza
oneshot config buf_size 4096
if [ "$RC" -ne 0 ] || [ "$OUT" != "+OK" ]; then
    echo "FALLO: config buf_size 4096: exit $RC, salida: $OUT" >&2
    kill "$CURL_PID" 2>/dev/null
    exit 1
fi
echo "buf_size: cambiado en caliente a mitad de una transferencia viva"

if ! wait "$CURL_PID"; then
    echo "FALLO: la transferencia viva no sobrevivio al cambio de buf_size" >&2
    exit 1
fi
got="$(sha256sum "$TMP/got_live.bin" | cut -d' ' -f1)"
if [ "$got" != "$want" ]; then
    echo "FALLO: la transferencia viva llego corrupta tras cambiar buf_size" >&2
    exit 1
fi
echo "buf_size: la transferencia viva (buffers viejos) termino integra"

# transferencia NUEVA, ya con el buf_size nuevo vigente
curl -s --max-time "$XFER_TIMEOUT" \
     --socks5-hostname "127.0.0.1:$PROXY_PORT" \
     "http://127.0.0.1:$HTTP_PORT/big.bin" -o "$TMP/got_new.bin"
if [ $? -ne 0 ]; then
    echo "FALLO: la transferencia nueva (post buf_size) fallo" >&2
    exit 1
fi
got_new="$(sha256sum "$TMP/got_new.bin" | cut -d' ' -f1)"
if [ "$got_new" != "$want" ]; then
    echo "FALLO: la transferencia nueva con buf_size 4096 llego corrupta" >&2
    exit 1
fi
echo "buf_size: una conexion nueva con el tamano actualizado tambien es integra"

echo "OK: config dinamica en caliente (timeout y buf_size) sin reiniciar"
exit 0

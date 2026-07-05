#!/bin/bash
#
# Prueba end-to-end del apagado ordenado.
#
# Levanta el proxy y un http.server local y baja un archivo grande a traves
# del proxy con la velocidad limitada (para que la transferencia dure varios
# segundos y haya ventana para senalar en el medio). Corre dos casos:
#   1. drenado: SIGTERM a mitad de transferencia -> el proxy deja de aceptar
#      conexiones nuevas pero la transferencia en curso termina integra
#      (sha256 igual al original) y el proceso sale solo con exit 0.
#   2. corte forzado: una 2da SIGTERM a mitad de drenado -> la transferencia
#      se corta ya (no espera a que termine) y el proxy sale con exit 0.
#
# Sale 0 si todo ok, 1 si algun caso fallo, 2 si falta una dependencia o
# fallo el build.
#
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
SIZE_MB=5
RATE=1M            # ~5s de transferencia: ventana comoda para senalar
XFER_TIMEOUT=60
EXIT_TIMEOUT=10    # cuanto esperar a que el proxy salga solo

for dep in curl python3 sha256sum; do
    command -v "$dep" >/dev/null 2>&1 || { echo "falta $dep" >&2; exit 2; }
done

make -C "$REPO" server >/dev/null || { echo "fallo el build" >&2; exit 2; }

TMP="$(mktemp -d)"
PROXY_PID=""
HTTP_PID=""
cleanup() {
    [ -n "$PROXY_PID" ] && kill -9 "$PROXY_PID" 2>/dev/null
    [ -n "$HTTP_PID" ]  && kill "$HTTP_PID"  2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0));
print(s.getsockname()[1]); s.close()'
}
HTTP_PORT="$(free_port)"

dd if=/dev/urandom of="$TMP/big.bin" bs=1M count="$SIZE_MB" status=none
want="$(sha256sum "$TMP/big.bin" | cut -d' ' -f1)"

python3 -m http.server "$HTTP_PORT" --directory "$TMP" >/dev/null 2>&1 &
HTTP_PID=$!

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
wait_listen "$HTTP_PID" "$HTTP_PORT" "http.server" || exit 2

# cada caso levanta su propio proxy (el caso anterior lo apaga)
start_proxy() {
    PROXY_PORT="$(free_port)"
    MGMT_PORT="$(free_port)"
    "$REPO/bin/server" -p "$PROXY_PORT" -P "$MGMT_PORT" >/dev/null 2>&1 &
    PROXY_PID=$!
    wait_listen "$PROXY_PID" "$PROXY_PORT" "proxy" || exit 2
}

# espera a que el proxy salga solo y devuelve su exit code en PROXY_RC;
# falla si sigue vivo despues de EXIT_TIMEOUT
wait_proxy_exit() {
    for _ in $(seq 1 $((EXIT_TIMEOUT * 10))); do
        kill -0 "$PROXY_PID" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "FALLO: el proxy no salio solo tras ${EXIT_TIMEOUT}s" >&2
        return 1
    fi
    wait "$PROXY_PID"
    PROXY_RC=$?
    PROXY_PID=""
    return 0
}

# ---- 1. drenado: la transferencia en curso termina, las nuevas se rechazan --
start_proxy

curl -s --max-time "$XFER_TIMEOUT" --limit-rate "$RATE" \
     --socks5-hostname "127.0.0.1:$PROXY_PORT" \
     "http://127.0.0.1:$HTTP_PORT/big.bin" -o "$TMP/got_drain.bin" &
CURL_PID=$!

sleep 1   # a esta velocidad la transferencia recien empieza
kill -TERM "$PROXY_PID"
sleep 0.3 # que el proxy procese la senal antes de probar el rechazo

if python3 -c "import socket,sys
s = socket.socket(); s.settimeout(2)
try: s.connect((\"127.0.0.1\", $PROXY_PORT))
except OSError: sys.exit(1)
sys.exit(0)"; then
    echo "FALLO: el proxy acepto una conexion nueva durante el drenado" >&2
    exit 1
fi
echo "drenado: conexion nueva rechazada tras la 1ra senal"

if ! wait "$CURL_PID"; then
    echo "FALLO: la transferencia en curso no sobrevivio al drenado" >&2
    exit 1
fi
got="$(sha256sum "$TMP/got_drain.bin" | cut -d' ' -f1)"
if [ "$got" != "$want" ]; then
    echo "FALLO: la transferencia drenada llego corrupta" >&2
    exit 1
fi
echo "drenado: ${SIZE_MB}MB integros con SIGTERM a mitad de transferencia"

wait_proxy_exit || exit 1
if [ "$PROXY_RC" -ne 0 ]; then
    echo "FALLO: el drenado termino con exit $PROXY_RC (esperaba 0)" >&2
    exit 1
fi
echo "drenado: el proxy salio solo con exit 0"

# ---- 2. corte forzado: la 2da senal no espera a que la transferencia termine
start_proxy

curl -s --max-time "$XFER_TIMEOUT" --limit-rate "$RATE" \
     --socks5-hostname "127.0.0.1:$PROXY_PORT" \
     "http://127.0.0.1:$HTTP_PORT/big.bin" -o "$TMP/got_force.bin" &
CURL_PID=$!

sleep 1
kill -TERM "$PROXY_PID"   # entra en drenado con la transferencia viva
sleep 0.5
kill -TERM "$PROXY_PID"   # corte forzado

# sin DNS en juego (IP literal) el corte no espera a ningun worker: la cota
# corta de EXIT_TIMEOUT ya valida que no se quedo drenando hasta el final
wait_proxy_exit || exit 1
if [ "$PROXY_RC" -ne 0 ]; then
    echo "FALLO: el corte forzado termino con exit $PROXY_RC (esperaba 0)" >&2
    exit 1
fi

if wait "$CURL_PID" && [ "$(stat -c%s "$TMP/got_force.bin")" -eq $((SIZE_MB * 1024 * 1024)) ]; then
    echo "FALLO: la transferencia termino completa; la 2da senal no corto" >&2
    exit 1
fi
echo "corte forzado: la 2da senal corto la transferencia y salio con exit 0"

echo "OK: apagado ordenado en ambos casos"
exit 0

#!/bin/bash
#
# Prueba end-to-end de integridad del relay.
#
# Levanta el proxy y un http.server local, baja un archivo de varios MB a
# traves del proxy y compara sha256 contra el original. El archivo es mucho
# mas grande que los buffers de 2048 bytes, asi que valida I/O parcial y
# backpressure con trafico real. Corre dos veces:
#   1. con curl --socks5-hostname (el camino tipico de un cliente real), y
#   2. con half_close_client.py, que ademas hace un half-close REAL
#      (shutdown SHUT_WR) que curl no ejercita.
#
# Sale 0 si todo ok, 1 si una transferencia fallo o llego corrupta, 2 si
# falta una dependencia o fallo el build.
#
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
. "$HERE/../lib.sh"
SIZE_MB=5
XFER_TIMEOUT=60

for dep in curl python3 sha256sum; do
    command -v "$dep" >/dev/null 2>&1 || { echo "falta $dep" >&2; exit 2; }
done

# siempre contra el binario recien compilado
make -C "$REPO" server >/dev/null || { echo "fallo el build" >&2; exit 2; }

TMP="$(mktemp -d)"
PROXY_PID=""
HTTP_PID=""
cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
    [ -n "$HTTP_PID" ]  && kill "$HTTP_PID"  2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# puertos dinamicos (los elige el kernel) para no colisionar entre corridas
PROXY_PORT="$(free_port)"
HTTP_PORT="$(free_port)"

dd if=/dev/urandom of="$TMP/big.bin" bs=1M count="$SIZE_MB" status=none

python3 -m http.server "$HTTP_PORT" --directory "$TMP" >/dev/null 2>&1 &
HTTP_PID=$!
"$REPO/bin/server" -p "$PROXY_PORT" >/dev/null 2>&1 &
PROXY_PID=$!

# esperar a que cada proceso escuche de verdad (y detectar si murio al nacer)
wait_listen "$HTTP_PID"  "$HTTP_PORT"  "http.server" || exit 2
wait_listen "$PROXY_PID" "$PROXY_PORT" "proxy"       || exit 2

want="$(sha256sum "$TMP/big.bin" | cut -d' ' -f1)"

# distingue "el relay fallo" de "un proceso murio en el medio"
check_alive() {
    kill -0 "$PROXY_PID" 2>/dev/null || echo "el proxy murio durante la prueba" >&2
    kill -0 "$HTTP_PID"  2>/dev/null || echo "el http.server murio durante la prueba" >&2
}

# ---- 1. integridad via curl -------------------------------------------------
if ! curl -s --max-time "$XFER_TIMEOUT" \
        --socks5-hostname "127.0.0.1:$PROXY_PORT" \
        "http://127.0.0.1:$HTTP_PORT/big.bin" -o "$TMP/got_curl.bin"; then
    check_alive
    echo "FALLO: curl no pudo bajar el archivo a traves del proxy" >&2
    exit 1
fi
got="$(sha256sum "$TMP/got_curl.bin" | cut -d' ' -f1)"
if [ "$got" != "$want" ]; then
    echo "FALLO: la descarga via curl llego corrupta" >&2
    exit 1
fi
echo "curl: ${SIZE_MB}MB integros a traves del proxy"

# ---- 2. integridad + half-close real ---------------------------------------
if ! timeout "$XFER_TIMEOUT" python3 "$HERE/half_close_client.py" \
        "$PROXY_PORT" "127.0.0.1" "$HTTP_PORT" "/big.bin" "$TMP/got_hc.bin"; then
    check_alive
    echo "FALLO: el cliente con half-close no recibio la respuesta completa" >&2
    exit 1
fi
got="$(sha256sum "$TMP/got_hc.bin" | cut -d' ' -f1)"
if [ "$got" != "$want" ]; then
    echo "FALLO: la descarga con half-close llego corrupta" >&2
    exit 1
fi
echo "half-close: ${SIZE_MB}MB integros con shutdown(SHUT_WR) explicito"

echo "OK: relay integro en ambos caminos"
exit 0

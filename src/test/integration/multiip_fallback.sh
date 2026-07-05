#!/bin/bash
#
# Prueba end-to-end del connect robusto multi-IP (T51).
#
# Con multiip_shim.c (LD_PRELOAD) el proxy resuelve nombres magicos a listas
# controladas de direcciones de loopback, y el http.server de origen escucha
# SOLO en 127.0.0.1, asi que 127.0.0.2/3 rechazan con ECONNREFUSED:
#
#   1. multiip-fallback.test   -> [127.0.0.2 caida, 127.0.0.1 viva]:
#      la descarga via curl tiene que llegar bien por la segunda direccion.
#   2. multiip-allrefused.test -> [127.0.0.2, 127.0.0.3] ambas caidas:
#      el cliente tiene que recibir REP 0x05 (connection refused) y el
#      proxy cerrar la conexion despues del reply.
#
# Sale 0 si ambos casos pasan, 1 si el fallback no anduvo o el REP es otro,
# 2 si falta una dependencia o fallo un build.
#
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
SIZE_MB=1
XFER_TIMEOUT=30

for dep in curl python3 sha256sum gcc; do
    command -v "$dep" >/dev/null 2>&1 || { echo "falta $dep" >&2; exit 2; }
done

# siempre contra el binario y el shim recien compilados
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

gcc -shared -fPIC -o "$TMP/multiip_shim.so" "$HERE/multiip_shim.c" -ldl \
    || { echo "fallo el build del shim" >&2; exit 2; }

# puertos dinamicos (los elige el kernel) para no colisionar entre corridas
free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0));
print(s.getsockname()[1]); s.close()'
}
PROXY_PORT="$(free_port)"
HTTP_PORT="$(free_port)"

dd if=/dev/urandom of="$TMP/big.bin" bs=1M count="$SIZE_MB" status=none

# --bind 127.0.0.1 es la clave del test: si escuchara en 0.0.0.0 tambien
# atenderia en 127.0.0.2/3 y no habria direcciones "caidas" que probar.
python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$TMP" \
    >/dev/null 2>&1 &
HTTP_PID=$!
LD_PRELOAD="$TMP/multiip_shim.so" "$REPO/bin/server" -p "$PROXY_PORT" \
    >/dev/null 2>&1 &
PROXY_PID=$!

# esperar a que cada proceso escuche de verdad (y detectar si murio al nacer)
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
wait_listen "$HTTP_PID"  "$HTTP_PORT"  "http.server" || exit 2
wait_listen "$PROXY_PID" "$PROXY_PORT" "proxy"       || exit 2

want="$(sha256sum "$TMP/big.bin" | cut -d' ' -f1)"

# distingue "la prueba fallo" de "un proceso murio en el medio"
check_alive() {
    kill -0 "$PROXY_PID" 2>/dev/null || echo "el proxy murio durante la prueba" >&2
    kill -0 "$HTTP_PID"  2>/dev/null || echo "el http.server murio durante la prueba" >&2
}

# ---- 1. fallback: la primera direccion rechaza, la segunda sirve -----------
if ! curl -s --max-time "$XFER_TIMEOUT" \
        --socks5-hostname "127.0.0.1:$PROXY_PORT" \
        "http://multiip-fallback.test:$HTTP_PORT/big.bin" -o "$TMP/got.bin"; then
    check_alive
    echo "FALLO: la descarga no llego (el proxy no probo la 2da direccion?)" >&2
    exit 1
fi
got="$(sha256sum "$TMP/got.bin" | cut -d' ' -f1)"
if [ "$got" != "$want" ]; then
    echo "FALLO: la descarga via fallback llego corrupta" >&2
    exit 1
fi
echo "fallback: ${SIZE_MB}MB integros con la primera direccion caida"

# ---- 2. todas caidas: REP 0x05 y cierre limpio ------------------------------
if ! timeout "$XFER_TIMEOUT" python3 "$HERE/rep_client.py" \
        "$PROXY_PORT" "multiip-allrefused.test" "$HTTP_PORT" 0x05; then
    check_alive
    echo "FALLO: con todas las direcciones caidas no llego REP 0x05" >&2
    exit 1
fi
echo "allrefused: REP 0x05 y cierre limpio con todas las direcciones caidas"

# el proxy tiene que seguir vivo y funcional despues de ambos casos
if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "FALLO: el proxy murio despues de las pruebas" >&2
    exit 1
fi

echo "OK: connect robusto ante FQDN multi-IP con direcciones caidas"
exit 0

# Helpers compartidos por los scripts de test (integration/ y stress/).
#
# Se usa despues de definir HERE y REPO:
#     . "$HERE/../lib.sh"
#
#   free_port                      imprime un puerto libre que elige el kernel
#   wait_listen <pid> <puerto> <nombre> [intentos]
#                                  espera a que <pid> ESCUCHE en <puerto>; falla si
#                                  el proceso murio o si no escucha a tiempo. Cada
#                                  intento son ~0.1s; el default (50) da ~5s, que
#                                  alcanza para un server normal. Bajo valgrind el
#                                  arranque es mucho mas lento: ahi se pasa mas.
#   mgmt <args...>                 corre bin/client contra el puerto de monitoreo
#                                  (requiere REPO, MGMT_PORT y ADMIN)
#   fail <mensaje>                 aborta con exit 1; si SERVER_LOG apunta a un
#                                  archivo legible, muestra sus ultimas lineas
#
# Cada helper vivia duplicado en los 7 scripts: un fix al reintento de
# wait_listen o al parseo habia que replicarlo a mano en todos.

# Los clientes .py importan socks5.py, y Python cachea el bytecode de todo modulo
# importado dejando un src/test/__pycache__/ adentro del arbol de fuentes (el
# script que corre como __main__ no se cachea; el modulo importado si). Ese cache
# no compra nada aca --un modulo de 70 lineas por proceso, en pruebas que ademas
# levantan un server y hablan TCP-- y ensucia el repo y el tarball de la entrega,
# que `make clean` no limpia. Se hereda a todo python3 que lancen los scripts.
export PYTHONDONTWRITEBYTECODE=1

free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0));
print(s.getsockname()[1]); s.close()'
}

wait_listen() {
    local pid=$1 port=$2 name=$3 tries=${4:-50}
    for _ in $(seq 1 "$tries"); do
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

mgmt() {
    "$REPO/bin/client" -P "$MGMT_PORT" -a "$ADMIN" "$@"
}

fail() {
    echo "FALLO: $1" >&2
    if [ -n "${SERVER_LOG:-}" ] && [ -r "${SERVER_LOG:-}" ]; then
        echo "--- ultimas lineas del log del server ---" >&2
        tail -5 "$SERVER_LOG" >&2
    fi
    exit 1
}

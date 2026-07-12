#!/usr/bin/env python3
"""
Establece N conexiones SOCKS5 completas (estado COPY) contra un origen local y
las SOSTIENE abiertas: el script mismo actúa de origen (listener propio),
completa HELLO + REQUEST, verifica un ping/pong por el relay en ambos sentidos
y después deja bytes extra en tránsito. Mientras duerme, el runner le manda
SIGTERM al server: el teardown ocurre con conexiones vivas en COPY (ambos fds
registrados, references == 2) y no debe fugar nada.

A diferencia de driver_connecting.py, este proceso tiene que seguir VIVO al
momento del SIGTERM (en COPY un EOF nuestro termina la conexión ordenadamente
y no quedaría nada que teardownear), por eso el runner lo corre en background.

Uso: driver_copy.py [puerto-proxy] [cantidad]
"""
import socket
import struct
import sys
import time
import os

# helpers SOCKS5 compartidos (src/test/socks5.py): recv_exact y el parseo
# del REPLY vivian duplicados en cada cliente
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from socks5 import recv_exact, read_reply  # noqa: E402

PROXY_HOST = "127.0.0.1"
PROXY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 11091
N          = int(sys.argv[2]) if len(sys.argv) > 2 else 8


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(N)
srv.settimeout(10)
origin_port = srv.getsockname()[1]

held = []
for _ in range(N):
    try:
        c = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=10)
        c.settimeout(10)
        c.sendall(b"\x05\x01\x00")
        if recv_exact(c, 2) != b"\x05\x00":
            raise OSError("hello rechazado")
        c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                  + struct.pack("!H", origin_port))
        _ver, rep, _atyp = read_reply(c)
        if rep != 0x00:
            raise OSError(f"REP={rep[1]:#04x}")
        o, _ = srv.accept()
        o.settimeout(10)
        # ping/pong por el relay: la conexion quedo firmemente en COPY
        c.sendall(b"ping")
        if recv_exact(o, 4) != b"ping":
            raise OSError("relay ida rota")
        o.sendall(b"pong")
        if recv_exact(c, 4) != b"pong":
            raise OSError("relay vuelta rota")
        # bytes extra en transito (mas que el buffer de 2048) sin drenar del
        # todo: el teardown agarra al relay en pleno trabajo
        c.sendall(b"x" * 4096)
        held.append((c, o))
    except OSError as e:
        print(f"driver: {e}", file=sys.stderr)

if not held:
    print(f"driver: no se pudo establecer ninguna conexion via "
          f"{PROXY_HOST}:{PROXY_PORT}. ¿esta corriendo el server?",
          file=sys.stderr)
    sys.exit(1)

print(f"driver: {len(held)} conexiones en COPY, sostenidas", flush=True)
# mantener todo abierto mientras el runner manda SIGTERM al server
time.sleep(6)

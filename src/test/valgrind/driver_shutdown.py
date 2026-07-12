#!/usr/bin/env python3
"""
Arma la mezcla de conexiones que el apagado ordenado tiene que limpiar y las
SOSTIENE mientras el runner señala al server:

  - N conexiones en COPY (relay activo con bytes en tránsito, como
    driver_copy.py): son las que el drenado debe dejar terminar y el corte
    forzado debe cerrar de un saque.
  - 1 conexión a medio HELLO (conecta y no manda nada): el barrido de la 1ª
    señal la cierra (no hay transferencia que drenar).
  - 1 sesión de monitoreo (TCP al puerto de mgmt, sostenida): el teardown
    tiene que cerrar su fd también.
  - 1 CONNECT a un FQDN "slow*" (el shim de DNS duerme 3s), en ambos modos:
    en drain, si la señal cae en esa ventana el barrido la saltea y la cierra
    resolve_done al notificar; en force, la 2ª señal cae con el getaddrinfo
    aún en vuelo y cubre el camino más delicado del teardown (el job de
    notificación embebido se drena antes del unregister que libera el struct).

Modos:
  drain: sostiene las COPY unos segundos y después cierra todo ordenadamente,
         para que el server (ya señalado) termine de drenar y salga solo.
  force: sostiene todo hasta que lo maten (el server sale por la 2ª señal con
         las conexiones aún vivas).

Uso: driver_shutdown.py <puerto-proxy> <puerto-mgmt> <drain|force> [n-copy]
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
PROXY_PORT = int(sys.argv[1])
MGMT_PORT  = int(sys.argv[2])
MODE       = sys.argv[3]
N          = int(sys.argv[4]) if len(sys.argv) > 4 else 6
HOLD_DRAIN = 6   # cuanto sostener las COPY en modo drain antes de soltar


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(N)
srv.settimeout(15)
origin_port = srv.getsockname()[1]

held = []      # pares (cliente, origen) en COPY
extras = []    # sockets que el server va a cerrar (no exigimos nada de ellos)

for _ in range(N):
    try:
        c = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=15)
        c.settimeout(15)
        c.sendall(b"\x05\x01\x00")
        if recv_exact(c, 2) != b"\x05\x00":
            raise OSError("hello rechazado")
        c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                  + struct.pack("!H", origin_port))
        _ver, rep, _atyp = read_reply(c)
        if rep != 0x00:
            raise OSError(f"REP={rep[1]:#04x}")
        o, _ = srv.accept()
        o.settimeout(15)
        c.sendall(b"ping")
        if recv_exact(o, 4) != b"ping":
            raise OSError("relay ida rota")
        o.sendall(b"pong")
        if recv_exact(c, 4) != b"pong":
            raise OSError("relay vuelta rota")
        # bytes extra en transito: el apagado agarra al relay en pleno trabajo
        c.sendall(b"x" * 4096)
        held.append((c, o))
    except OSError as e:
        print(f"driver: {e}", file=sys.stderr)

if not held:
    print(f"driver: ninguna conexion COPY via {PROXY_HOST}:{PROXY_PORT}. "
          f"¿esta corriendo el server?", file=sys.stderr)
    sys.exit(1)

# conexion a medio HELLO: no manda nada, el barrido la cierra
try:
    extras.append(socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=15))
except OSError as e:
    print(f"driver: half-hello: {e}", file=sys.stderr)

# sesion de monitoreo viva (solo TCP: alcanza para tener su fd registrado)
try:
    extras.append(socket.create_connection((PROXY_HOST, MGMT_PORT), timeout=15))
except OSError as e:
    print(f"driver: mgmt: {e}", file=sys.stderr)

# ultima, justo antes del "ready": asi la ventana de 3s de RESOLVING recien
# arranca cuando el runner ve la linea y manda la(s) señal(es)
try:
    r = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=15)
    r.settimeout(15)
    r.sendall(b"\x05\x01\x00")
    if recv_exact(r, 2) != b"\x05\x00":
        raise OSError("hello rechazado (slow)")
    host = b"slow.test"
    r.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host
              + struct.pack("!H", 80))
    extras.append(r)
except OSError as e:
    print(f"driver: resolving: {e}", file=sys.stderr)

print(f"driver: {len(held)} en COPY + {len(extras)} extras, modo {MODE}",
      flush=True)

if MODE == "drain":
    time.sleep(HOLD_DRAIN)
    for c, o in held:
        c.close()
        o.close()
    for s in extras:
        s.close()
else:
    time.sleep(60)   # force: el runner nos mata en su cleanup

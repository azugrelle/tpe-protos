#!/usr/bin/env python3
"""
Abre N conexiones SOCKS5 contra el proxy y las deja colgadas en el estado
CONNECTING: el destino es 192.0.2.1 (TEST-NET-1, RFC5737), que no rutea, así que
el connect del server queda en EINPROGRESS y la conexion queda con su
origin_resolution alocado. Los sockets se mantienen abiertos para que, cuando el
runner le mande SIGTERM al server, el teardown ocurra justo en esa ventana.

Uso: driver_connecting.py [puerto-proxy] [cantidad]
"""
import socket
import struct
import sys
import time

PROXY_HOST = "127.0.0.1"
PROXY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 11090
DEST       = "192.0.2.1"
N          = int(sys.argv[2]) if len(sys.argv) > 2 else 8

held = []
for _ in range(N):
    try:
        c = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=3)
        c.sendall(b"\x05\x01\x00")            # HELLO no-auth
        c.recv(2)                              # respuesta del hello (inmediata)
        req = b"\x05\x01\x00\x01" + socket.inet_aton(DEST) + struct.pack("!H", 80)
        c.sendall(req)                         # REQUEST: dispara connect -> CONNECTING
        held.append(c)
    except OSError as e:
        print(f"driver: {e}", file=sys.stderr)

if not held:
    print(f"driver: no se pudo conectar al proxy en {PROXY_HOST}:{PROXY_PORT}. "
          f"¿está corriendo el server en ese puerto? Este script no lo arranca; "
          f"usá leak_connecting_teardown.sh o levantá ./bin/server primero.",
          file=sys.stderr)
    sys.exit(1)

print(f"driver: {len(held)} conexiones en CONNECTING, sostenidas")
# mantener los sockets abiertos mientras el runner manda SIGTERM al server
time.sleep(6)

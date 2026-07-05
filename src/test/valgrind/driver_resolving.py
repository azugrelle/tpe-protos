#!/usr/bin/env python3
"""
Abre N conexiones SOCKS5 con destino FQDN (ATYP 0x03) contra el proxy, para
poblar el estado RESOLVING y sus alrededores en el momento del SIGTERM:

  - "slow.test.example": con el shim de DNS lento cargado en el server, la
    resolución duerme 3s en el hilo -> la conexión queda EN RESOLVING cuando
    el runner mata al server (la ventana que protege resolve_shutdown_wait).
  - "localhost" a un puerto cerrado: recorre el camino completo del hilo
    (RESOLVING -> notify -> connect) antes del SIGTERM.
  - "no-existe-<x>.invalid": camino de error del hilo (REP 0x04).

Los sockets se mantienen abiertos para que el teardown ocurra con las
conexiones vivas.

Uso: driver_resolving.py [puerto-proxy] [cantidad]
"""
import socket
import struct
import sys
import time

PROXY_HOST = "127.0.0.1"
PROXY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 11092
N          = int(sys.argv[2]) if len(sys.argv) > 2 else 9

DESTS = [
    ("slow.test.example", 80),      # queda en RESOLVING (shim: 3s)
    ("localhost", 1),               # resuelve rápido, connect rechazado
    ("no-existe-9x7z.invalid", 80), # no resuelve, REP 0x04
]

def request(name: str, port: int) -> bytes:
    host = name.encode()
    return (b"\x05\x01\x00\x03" + bytes([len(host)]) + host
            + struct.pack("!H", port))

held = []
for i in range(N):
    name, port = DESTS[i % len(DESTS)]
    try:
        c = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=5)
        c.sendall(b"\x05\x01\x00")     # HELLO no-auth
        c.recv(2)                      # respuesta del hello (inmediata)
        c.sendall(request(name, port)) # REQUEST -> RESOLVING
        held.append(c)
    except OSError as e:
        print(f"driver: {e}", file=sys.stderr)

if not held:
    print(f"driver: no se pudo conectar al proxy en {PROXY_HOST}:{PROXY_PORT}. "
          f"¿está corriendo el server en ese puerto? Este script no lo arranca; "
          f"usá leak_resolving_teardown.sh o levantá ./bin/server primero.",
          file=sys.stderr)
    sys.exit(1)

print(f"driver: {len(held)} conexiones con REQUEST FQDN enviado, sostenidas")
# mantener los sockets abiertos mientras el runner manda SIGTERM al server
time.sleep(10)

#!/usr/bin/env python3
"""
Ejercita los caminos del connect robusto multi-IP contra un proxy que
corre con multiip_shim.so precargado, para que valgrind audite fds y memoria
del retry de candidatos:

  - "multiip-fallback.test": la 1ra dirección (127.0.0.2) rechaza y la 2da
    (127.0.0.1, el listener de este driver) conecta -> el fd del candidato
    caído tiene que cerrarse y la lista liberarse una sola vez al conectar.
  - "multiip-allrefused.test": todas rechazan -> agotamiento, REP 0x05 y
    liberación de la lista en connect_fail.
  - clientes que cortan la conexión apenas mandado el REQUEST: el proxy
    descubre el cierre recién al escribir el REPLY; la limpieza de la
    resolución debe pasar igual (socks5_cleanup).

El propio driver escucha en 127.0.0.1:0 y usa ese puerto como destino, así el
runner no coordina puertos: el puerto viaja dentro del REQUEST. Los sockets
se mantienen abiertos para que el SIGTERM agarre conexiones vivas.

Uso: driver_multiip.py [puerto-proxy] [cantidad]
"""
import socket
import struct
import sys
import time

PROXY_HOST = "127.0.0.1"
PROXY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 11093
N          = int(sys.argv[2]) if len(sys.argv) > 2 else 12

# origen vivo SOLO en 127.0.0.1: 127.0.0.2/3 del shim rechazan. No hace falta
# accept(): el handshake TCP lo completa el backlog del listen.
origin = socket.socket()
origin.bind(("127.0.0.1", 0))
origin.listen(16)
ORIGIN_PORT = origin.getsockname()[1]

CASES = [
    ("multiip-fallback.test",   True),    # retry + conexión: sostener
    ("multiip-allrefused.test", True),    # agotamiento, REP 0x05: sostener
    ("multiip-fallback.test",   False),   # cortar apenas mandado el REQUEST
]

def request(name: str, port: int) -> bytes:
    host = name.encode()
    return (b"\x05\x01\x00\x03" + bytes([len(host)]) + host
            + struct.pack("!H", port))

held = []
for i in range(N):
    name, hold = CASES[i % len(CASES)]
    try:
        c = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=5)
        c.sendall(b"\x05\x01\x00")               # HELLO no-auth
        c.recv(2)                                # respuesta del hello
        c.sendall(request(name, ORIGIN_PORT))    # REQUEST -> retry multi-IP
        if hold:
            held.append(c)
        else:
            c.close()                            # corte con el connect en vuelo
    except OSError as e:
        print(f"driver: {e}", file=sys.stderr)

if not held:
    print(f"driver: no se pudo conectar al proxy en {PROXY_HOST}:{PROXY_PORT}. "
          f"¿está corriendo el server con el shim en ese puerto? Este script "
          f"no lo arranca; usá leak_multiip_teardown.sh.", file=sys.stderr)
    sys.exit(1)

print(f"driver: {len(held)} conexiones multi-IP sostenidas "
      f"(origen en 127.0.0.1:{ORIGIN_PORT})")
# mantener los sockets abiertos mientras el runner manda SIGTERM al server
time.sleep(10)

#!/usr/bin/env python3
"""
Cliente SOCKS5 mínimo que ejercita un half-close REAL: hace CONNECT a través
del proxy, manda un GET HTTP/1.0, cierra su lado de escritura con
shutdown(SHUT_WR) y valida que igual recibe la respuesta completa hasta EOF.

curl nunca hace shutdown(SHUT_WR), así que este camino (propagar el FIN sin
perder los bytes en vuelo y mantener vivo el sentido origen→cliente) solo se
puede probar con un cliente a mano como este.

Uso: half_close_client.py <puerto-proxy> <dest-host> <dest-port> <path> <out>
Deja el body de la respuesta en <out>. Sale 0 si la respuesta fue 200 y llegó
completa (Content-Length coincide), 1 ante cualquier problema.
"""
import socket
import struct
import sys

PROXY_HOST = "127.0.0.1"


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError(f"EOF esperando {n} bytes (llegaron {len(data)})")
        data += chunk
    return data


def die(msg):
    print(f"half_close_client: {msg}", file=sys.stderr)
    sys.exit(1)


if len(sys.argv) != 6:
    die(__doc__)

proxy_port = int(sys.argv[1])
dest_host  = sys.argv[2]
dest_port  = int(sys.argv[3])
path       = sys.argv[4]
out_file   = sys.argv[5]

try:
    c = socket.create_connection((PROXY_HOST, proxy_port), timeout=30)
except OSError as e:
    die(f"no pude conectar al proxy en {PROXY_HOST}:{proxy_port}: {e}")

c.settimeout(30)

# HELLO no-auth
c.sendall(b"\x05\x01\x00")
if recv_exact(c, 2) != b"\x05\x00":
    die("el HELLO no fue aceptado")

# REQUEST: CONNECT con ATYP DOMAIN (el proxy resuelve el host)
host = dest_host.encode()
c.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host
          + struct.pack("!H", dest_port))

# REPLY: VER REP RSV ATYP BND.ADDR BND.PORT (largo variable segun ATYP)
ver, rep, _, atyp = recv_exact(c, 4)
if rep != 0x00:
    die(f"CONNECT rechazado: REP={rep:#04x}")
if atyp == 0x01:
    recv_exact(c, 4 + 2)
elif atyp == 0x04:
    recv_exact(c, 16 + 2)
elif atyp == 0x03:
    recv_exact(c, recv_exact(c, 1)[0] + 2)
else:
    die(f"ATYP desconocido en el reply: {atyp}")

# pedido + half-close: no mandamos nada mas, pero seguimos leyendo
c.sendall(f"GET {path} HTTP/1.0\r\n\r\n".encode())
c.shutdown(socket.SHUT_WR)

data = b""
while True:
    chunk = c.recv(65536)
    if not chunk:
        break
    data += chunk
c.close()

if b"\r\n\r\n" not in data:
    die(f"respuesta sin headers completos ({len(data)} bytes)")
headers, body = data.split(b"\r\n\r\n", 1)
status = headers.split(b"\r\n", 1)[0]
if b"200" not in status:
    die(f"status inesperado: {status!r}")

for line in headers.split(b"\r\n"):
    if line.lower().startswith(b"content-length:"):
        expected = int(line.split(b":", 1)[1])
        if len(body) != expected:
            die(f"body incompleto: {len(body)} de {expected} bytes")

with open(out_file, "wb") as f:
    f.write(body)
print(f"half_close_client: {status.decode()} body={len(body)} bytes")

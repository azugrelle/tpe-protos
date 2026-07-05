#!/usr/bin/env python3
"""
Cliente SOCKS5 mínimo que valida el byte REP del REPLY de un CONNECT.

curl no sirve para esto: ante un CONNECT rechazado solo reporta "falló", sin
exponer QUÉ código devolvió el proxy. Este cliente negocia hello + request,
lee el REPLY completo y compara el REP contra el esperado; si el esperado es
de error, valida además que el proxy cierra la conexión después del REPLY
(RFC 1928 §6: tras un reply de error se cierra).

Uso: rep_client.py <puerto-proxy> <dest-host> <dest-port> <rep-esperado>
<rep-esperado> en decimal o hex (p.ej. 0x05). Sale 0 si el REPLY está bien
formado y el REP coincide, 1 ante cualquier otra cosa.
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
    print(f"rep_client: {msg}", file=sys.stderr)
    sys.exit(1)


if len(sys.argv) != 5:
    die(__doc__)

proxy_port   = int(sys.argv[1])
dest_host    = sys.argv[2]
dest_port    = int(sys.argv[3])
expected_rep = int(sys.argv[4], 0)

try:
    c = socket.create_connection((PROXY_HOST, proxy_port), timeout=30)
except OSError as e:
    die(f"no pude conectar al proxy en {PROXY_HOST}:{proxy_port}: {e}")
c.settimeout(30)

try:
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
    if ver != 0x05:
        die(f"VER inesperada en el reply: {ver:#04x}")
    if atyp == 0x01:
        recv_exact(c, 4 + 2)
    elif atyp == 0x04:
        recv_exact(c, 16 + 2)
    elif atyp == 0x03:
        recv_exact(c, recv_exact(c, 1)[0] + 2)
    else:
        die(f"ATYP desconocido en el reply: {atyp}")

    if rep != expected_rep:
        die(f"REP={rep:#04x}, esperaba {expected_rep:#04x}")

    # tras un reply de error el proxy debe cerrar: esperamos EOF, no cuelgue
    if expected_rep != 0x00:
        if c.recv(1) != b"":
            die("el proxy no cerró la conexión tras el reply de error")
except OSError as e:
    die(str(e))
finally:
    c.close()

print(f"rep_client: REP={rep:#04x} como se esperaba")

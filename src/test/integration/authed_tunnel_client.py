#!/usr/bin/env python3
"""
Cliente SOCKS5 autenticado que sostiene un túnel abierto a demanda.

rep_client.py negocia no-auth y cierra apenas valida el REPLY; acá se ejercita
el otro camino: subnegociación usuario/contraseña (RFC 1929), CONNECT a un
destino IPv4 y un eco de ida y vuelta para forzar bytes relayados en ambos
sentidos. Después imprime TUNNEL_UP por stdout y queda bloqueado leyendo
stdin: el túnel sigue vivo hasta que el orquestador escribe una línea (o
cierra el pipe), lo que permite consultar las métricas del proxy con la
conexión abierta y de nuevo después de cerrarla.

Uso: authed_tunnel_client.py <puerto-proxy> <usuario> <password> <dest-ip> <dest-port>
Sale 0 si la negociación y el eco anduvieron, 1 ante cualquier error.
"""
import socket
import struct
import sys

PROXY_HOST = "127.0.0.1"
PAYLOAD = b"eco-a-traves-del-proxy\n"


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError(f"EOF esperando {n} bytes (llegaron {len(data)})")
        data += chunk
    return data


def die(msg):
    print(f"authed_tunnel_client: {msg}", file=sys.stderr)
    sys.exit(1)


if len(sys.argv) != 6:
    die(__doc__)

proxy_port = int(sys.argv[1])
username   = sys.argv[2].encode()
password   = sys.argv[3].encode()
dest_ip    = sys.argv[4]
dest_port  = int(sys.argv[5])

try:
    c = socket.create_connection((PROXY_HOST, proxy_port), timeout=30)
except OSError as e:
    die(f"no pude conectar al proxy en {PROXY_HOST}:{proxy_port}: {e}")
c.settimeout(30)

try:
    # HELLO ofreciendo solo usuario/contraseña
    c.sendall(b"\x05\x01\x02")
    if recv_exact(c, 2) != b"\x05\x02":
        die("el proxy no eligió el método usuario/contraseña")

    # subnegociación RFC 1929
    c.sendall(b"\x01" + bytes([len(username)]) + username
              + bytes([len(password)]) + password)
    if recv_exact(c, 2) != b"\x01\x00":
        die("la autenticación fue rechazada")

    # REQUEST: CONNECT con ATYP IPv4 (destino local, sin pasar por DNS)
    c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(dest_ip)
              + struct.pack("!H", dest_port))
    ver, rep, _, atyp = recv_exact(c, 4)
    if ver != 0x05 or rep != 0x00:
        die(f"REPLY con VER={ver:#04x} REP={rep:#04x}, esperaba éxito")
    if atyp == 0x01:
        recv_exact(c, 4 + 2)
    elif atyp == 0x04:
        recv_exact(c, 16 + 2)
    elif atyp == 0x03:
        recv_exact(c, recv_exact(c, 1)[0] + 2)
    else:
        die(f"ATYP desconocido en el reply: {atyp}")

    # eco de ida y vuelta: garantiza bytes relayados por el proxy
    c.sendall(PAYLOAD)
    if recv_exact(c, len(PAYLOAD)) != PAYLOAD:
        die("el eco volvió corrupto a través del túnel")

    # túnel listo: avisar y sostenerlo hasta que el orquestador lo suelte
    print("TUNNEL_UP", flush=True)
    sys.stdin.readline()
except OSError as e:
    die(str(e))
finally:
    c.close()

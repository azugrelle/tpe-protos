#!/usr/bin/env python3
"""
Abre y sostiene N tuneles SOCKS5 autenticados en un solo proceso (500
procesos de un tunel cada uno serian mucho mas pesados que el server bajo
prueba). Cada tunel hace el handshake completo (HELLO, subnegociacion
usuario/contrasenia, CONNECT a un destino IPv4 literal) y un eco de ida y
vuelta contra hold_server.py para confirmar que el relay quedo operativo.

Despues de la fase de apertura queda esperando comandos por stdin, para que
el orquestador (max_connections.sh) pueda interrogar el server con los
tuneles vivos:

  probe      intenta abrir UN tunel mas   -> "PROBE UP" | "PROBE REJECTED <sintoma>"
  echo       eco por un tunel ya abierto  -> "ECHO OK" | "ECHO FAIL <detalle>"
  close <k>  cierra k tuneles             -> "CLOSED <k> <restantes>"
  count      cantidad de tuneles abiertos -> "COUNT <n>"
  quit       cierra todo y termina

La fase de apertura imprime una sola linea de estado:
  "UP <n>"                  se abrieron los <target> pedidos
  "OPEN_FAIL <n> <sintoma>" fallo el tunel n+1; quedan n abiertos

Uso: concurrent_tunnels.py <puerto-proxy> <usuario> <password> <dest-ip> <dest-port> <target>
"""
import random
import socket
import struct
import sys
import os

# helpers SOCKS5 compartidos (src/test/socks5.py): recv_exact y el parseo
# del REPLY vivian duplicados en cada cliente
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from socks5 import SocksProtocol, recv_exact, read_reply  # noqa: E402

PROXY_HOST = "127.0.0.1"
PAYLOAD = b"eco-de-prueba-de-estres\n"
TIMEOUT = 10


class TunnelRejected(Exception):
    """El proxy no completo el handshake; el sintoma dice como fallo."""


def open_tunnel(proxy_port, user, password, dest_ip, dest_port):
    try:
        c = socket.create_connection((PROXY_HOST, proxy_port), timeout=TIMEOUT)
    except ConnectionRefusedError:
        raise TunnelRejected("connect-rechazado")
    except socket.timeout:
        raise TunnelRejected("timeout-de-connect")
    except OSError as e:
        # cualquier otro fallo del connect --tipicamente EMFILE ("Too many open
        # files"), realista cerca del techo de fds que esta prueba busca-- es un
        # rechazo mas, no un crash: sin esto el proceso moria con un traceback y
        # el orquestador se quedaba sin su linea de estado.
        raise TunnelRejected(f"connect-errno-{e.errno}")

    c.settimeout(TIMEOUT)
    # el socket se cierra en TODOS los caminos de rechazo (tambien los que se
    # lanzan a mano, como reply-rep y eco-corrupto): dejarlo al refcounting de
    # CPython haria que cada probe del bucle de sondeo filtre un fd
    ok = False
    try:
        # HELLO ofreciendo solo usuario/contrasenia
        c.sendall(b"\x05\x01\x02")
        if recv_exact(c, 2) != b"\x05\x02":
            raise TunnelRejected("metodo-inesperado-en-hello")

        # subnegociacion RFC 1929
        c.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
        if recv_exact(c, 2) != b"\x01\x00":
            raise TunnelRejected("credenciales-rechazadas")

        # CONNECT a IPv4 literal (sin DNS: no ensucia la medicion con hilos
        # de resolucion)
        c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(dest_ip)
                  + struct.pack(">H", dest_port))
        _ver, rep, _atyp = read_reply(c)
        if rep != 0x00:
            raise TunnelRejected(f"reply-rep-0x{rep:02x}")

        # eco de ida y vuelta: fuerza bytes relayados en ambos sentidos
        c.sendall(PAYLOAD)
        if recv_exact(c, len(PAYLOAD)) != PAYLOAD:
            raise TunnelRejected("eco-corrupto")
        ok = True
        return c
    except SocksProtocol as e:
        raise TunnelRejected(str(e))
    except EOFError:
        # el sintoma del tope de conexiones: el proxy acepta el TCP y cierra
        # sin ningun byte de reply SOCKS
        raise TunnelRejected("eof-sin-reply-socks")
    except socket.timeout:
        raise TunnelRejected("timeout-en-handshake")
    except ConnectionResetError:
        # variante del rechazo en el tope: el server cierra con bytes del
        # cliente ya en vuelo y la pila responde RST en vez de FIN
        raise TunnelRejected("reset-sin-reply-socks")
    except OSError as e:
        raise TunnelRejected(f"errno-{e.errno}")
    finally:
        if not ok:
            c.close()


def say(msg):
    print(msg, flush=True)


if len(sys.argv) != 7:
    print(__doc__, file=sys.stderr)
    sys.exit(1)

proxy_port = int(sys.argv[1])
user       = sys.argv[2].encode()
password   = sys.argv[3].encode()
dest_ip    = sys.argv[4]
dest_port  = int(sys.argv[5])
target     = int(sys.argv[6])

tunnels = []

# ---- fase de apertura -------------------------------------------------------
status = None
for i in range(target):
    try:
        tunnels.append(open_tunnel(proxy_port, user, password, dest_ip, dest_port))
    except TunnelRejected as e:
        status = f"OPEN_FAIL {len(tunnels)} {e}"
        break
    if (i + 1) % 50 == 0:
        print(f"  {i + 1} tuneles abiertos...", file=sys.stderr, flush=True)
if status is None:
    status = f"UP {len(tunnels)}"
say(status)

# ---- loop de comandos -------------------------------------------------------
for line in sys.stdin:
    parts = line.split()
    if not parts:
        continue
    cmd = parts[0]

    if cmd == "probe":
        try:
            tunnels.append(open_tunnel(proxy_port, user, password,
                                       dest_ip, dest_port))
            say("PROBE UP")
        except TunnelRejected as e:
            say(f"PROBE REJECTED {e}")
    elif cmd == "echo":
        if not tunnels:
            say("ECHO FAIL sin-tuneles-abiertos")
            continue
        t = random.choice(tunnels)
        try:
            t.sendall(PAYLOAD)
            ok = recv_exact(t, len(PAYLOAD)) == PAYLOAD
            say("ECHO OK" if ok else "ECHO FAIL eco-corrupto")
        except (OSError, EOFError) as e:
            say(f"ECHO FAIL {e}")
    elif cmd == "close" and len(parts) == 2:
        k = min(int(parts[1]), len(tunnels))
        for _ in range(k):
            tunnels.pop().close()
        say(f"CLOSED {k} {len(tunnels)}")
    elif cmd == "count":
        say(f"COUNT {len(tunnels)}")
    elif cmd == "quit":
        break
    else:
        say(f"ERR comando-desconocido {cmd}")

for t in tunnels:
    t.close()

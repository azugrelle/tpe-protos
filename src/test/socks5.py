"""
Helpers SOCKS5 compartidos por los clientes de prueba (integration/, stress/ y
valgrind/). Antes cada cliente traia su propia copia de `recv_exact` y del
parseo del REPLY: un fix al handshake habia que replicarlo a mano en 6 archivos.

Los helpers solo hacen I/O y devuelven lo leido; NO deciden como reportar un
fallo. Eso es justamente lo que difiere entre los clientes (unos hacen die() y
salen, otros lanzan TunnelRejected para contarlo como rechazo), asi que la
politica de error queda en cada uno.

Para importarlo desde un subdirectorio de src/test/:

    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    from socks5 import recv_exact, read_reply
"""
import socket

PROXY_HOST = "127.0.0.1"


class SocksError(OSError, EOFError):
    """
    Fallo hablando SOCKS5.

    Hereda de OSError Y de EOFError a proposito: las copias que este modulo
    reemplaza lanzaban una u otra (los clientes de integration/ y los drivers
    atrapaban OSError; concurrent_tunnels.py, EOFError), y asi ninguno de los
    `except` ya escritos deja de andar.
    """


class SocksEOF(SocksError):
    """El peer cerro antes de mandar los bytes esperados."""


class SocksProtocol(SocksError):
    """El peer contesto algo que no respeta el protocolo."""


def recv_exact(sock, n):
    """Lee exactamente n bytes, o SocksEOF si el peer cierra antes."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise SocksEOF(f"EOF esperando {n} bytes (llegaron {len(data)})")
        data += chunk
    return data


def read_reply(sock):
    """
    Lee el REPLY del CONNECT (VER REP RSV ATYP BND.ADDR BND.PORT) y consume
    BND.ADDR + BND.PORT segun el ATYP, que es lo que deja el stream alineado
    para los datos del tunel. Devuelve (ver, rep, atyp).

    Un ATYP fuera de 1/3/4 no se puede saltear (no se sabe cuanto mide BND.ADDR):
    seguir leyendo desalinearia el stream en silencio, asi que es SocksProtocol.
    """
    ver, rep, _rsv, atyp = recv_exact(sock, 4)
    if atyp == 0x01:                                  # IPv4
        recv_exact(sock, 4 + 2)
    elif atyp == 0x04:                                # IPv6
        recv_exact(sock, 16 + 2)
    elif atyp == 0x03:                                # dominio: 1 byte de largo
        recv_exact(sock, recv_exact(sock, 1)[0] + 2)
    else:
        raise SocksProtocol(f"ATYP desconocido en el reply: {atyp:#04x}")
    return ver, rep, atyp

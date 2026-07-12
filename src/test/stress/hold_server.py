#!/usr/bin/env python3
"""
Origen local para las pruebas de estres: acepta muchas conexiones TCP
concurrentes, hace eco de todo lo que recibe y mantiene cada conexion abierta
hasta que el cliente la cierre. asyncio en un solo proceso aguanta los cientos
de conexiones simultaneas que la prueba de concurrencia necesita sin un thread
por cliente.

Uso: hold_server.py <puerto>
"""
import asyncio
import sys


async def handle(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


async def main(port):
    server = await asyncio.start_server(handle, "127.0.0.1", port)
    async with server:
        await server.serve_forever()


if len(sys.argv) != 2:
    print(__doc__, file=sys.stderr)
    sys.exit(1)

asyncio.run(main(int(sys.argv[1])))

# Pruebas de fugas con valgrind

Pruebas manuales de memoria del proxy, complementarias a los tests unitarios de
`src/test/`. Requieren `valgrind` instalado.

## `leak_connecting_teardown.sh`

Verifica que no se filtre la resolución del origen (`origin_resolution`) cuando el
server se apaga con conexiones en vuelo. Abre varias conexiones que quedan en el
estado `CONNECTING` (destino no ruteable, el `connect` queda en `EINPROGRESS`) y
le manda `SIGTERM` al server: el teardown debe liberar cada `addrinfo`.

```sh
./src/test/valgrind/leak_connecting_teardown.sh
```

Sale con código `0` si no hay fugas, `1` si valgrind reporta errores/fugas, `2`
si falta valgrind o falla el build. Usa `driver_connecting.py` como generador de
carga (se le puede pasar puerto y cantidad de conexiones).

## `leak_copy_teardown.sh`

Verifica que el teardown con conexiones **en pleno relay** (estado `COPY`) no
fugue: ambos fds registrados, `references == 2`, buffers con bytes en tránsito.
Establece varias conexiones SOCKS5 completas contra un origen local
(`driver_copy.py`, que corre en background porque tiene que seguir vivo al
momento del SIGTERM) y apaga el server con el relay trabajando: el refcount
debe llevar cada conexión a `cleanup` exactamente una vez.

```sh
./src/test/valgrind/leak_copy_teardown.sh
```

Mismos códigos de salida que el test de CONNECTING.

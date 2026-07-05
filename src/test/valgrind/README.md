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

Sale con código `0` si no hay fugas ni errores de memoria, `1` si valgrind
reporta errores/fugas, `2` si falta valgrind, falla el build o el escenario no
llega a establecerse. Los descriptores abiertos al exit se imprimen a título
informativo (siempre figura el fd del `--log-file` de valgrind, y el teardown
no cierra los fds de conexiones aún vivas al SIGTERM — pendiente de
robustez): no son parte del veredicto. Usa `driver_connecting.py` como generador de
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

## `leak_resolving_teardown.sh`

Verifica la sincronización del apagado con el DNS asíncrono: el server recibe
`SIGTERM` con **resoluciones en vuelo** (hilos corriendo `getaddrinfo`). El
apagado es determinístico porque `main` llama `resolve_shutdown_wait()` antes
de destruir el selector: espera a que todos los hilos de resolución terminen,
así ninguno escribe sobre memoria liberada ni notifica sobre un mutex
destruido. Sin esa espera este test reporta invalid writes, no solo fugas.

Para que el SIGTERM caiga siempre dentro de la ventana, el server corre con
`slowdns_shim.c` precargado (`LD_PRELOAD`): el `getaddrinfo` de los hosts
`slow*` duerme 3 segundos y resuelve como `localhost`. El driver
(`driver_resolving.py`, en background) mezcla destinos FQDN lentos, rápidos e
irresolubles para poblar `RESOLVING` y sus dos salidas.

```sh
./src/test/valgrind/leak_resolving_teardown.sh
```

Mismos códigos de salida que los anteriores.

## `leak_multiip_teardown.sh`

Audita los recursos del **connect robusto multi-IP**: el retry de
candidatos multiplica fds (uno por dirección probada) y mantiene viva la lista
de `addrinfo` entre intentos, así que es el candidato perfecto a fuga. El
server corre con `multiip_shim.c` precargado (el de `src/test/integration/`):
los nombres mágicos resuelven a varias direcciones de loopback donde solo
`127.0.0.1` tiene un listener (el del propio driver). `driver_multiip.py`
mezcla fallbacks que terminan conectando, agotamientos con REP `0x05` y
clientes que cortan apenas mandado el REQUEST; después cae el `SIGTERM` con
conexiones vivas.

Valgrind valida que cada candidato fallido cerró su fd (`--track-fds`), que
cada lista se libera exactamente una vez —también cuando el cliente corta
antes del REPLY— y que el avance de candidatos no toca memoria inválida. Las
listas las fabrica el shim con mallocs propios, así que una resolución sin
liberar aparece como `definitely lost`.

```sh
./src/test/valgrind/leak_multiip_teardown.sh
```

Mismos códigos de salida que los anteriores.

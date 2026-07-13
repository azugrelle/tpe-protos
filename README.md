# TPE - Protocolos de Comunicación

Servidor **proxy SOCKSv5** (RFC 1928) no bloqueante y single-thread, con
autenticación usuario/contraseña (RFC 1929) y administración en caliente:

- **Servidor SOCKSv5**: salida TCP a destinos IPv4, IPv6 y FQDN, con resolución
  DNS asíncrona y reintento sobre todas las direcciones del destino.
- **Protocolo de monitoreo**: protocolo de texto propio, en un puerto aparte,
  para consultar métricas, gestionar usuarios y cambiar la configuración en
  runtime sin reiniciar ([especificación](doc/rfc-monitoreo.md)).
- **Cliente de monitoreo**: aplicación de terminal, interactiva o por comando
  único, para operar el servidor.
- **Métricas y registro de accesos**: conexiones históricas y concurrentes,
  bytes transferidos, usuarios activos y access log por usuario.

<details>
  <summary>Contenidos</summary>
  <ol>
    <li><a href="#instalación">Instalación</a></li>
    <li><a href="#instrucciones">Instrucciones</a></li>
    <li><a href="#limpieza">Limpieza</a></li>
    <li><a href="#estructura">Estructura</a></li>
    <li><a href="#integrantes">Integrantes</a></li>
  </ol>
</details>

## Instalación:

### Dependencias

- **Compilar** el servidor y el cliente: `gcc` (C11) y `make`.

```sh
make        # compila server y client en ./bin
```

- **Correr los tests**: además hace falta el framework de unit testing
  [`check`](https://libcheck.github.io/check/) (se usa también en los tests de la cátedra
  en `src/test/`). En Debian/Ubuntu:

```sh
sudo apt-get install check
make test   # compila y corre la suite de tests
```

Sin `check` instalado, `make server`/`make client` funcionan igual; solo `make test` lo requiere.

### Agregar un test nuevo

Los tests viven en `src/test/` y usan el framework [`check`](https://libcheck.github.io/check/).

1. **Crear el archivo** `src/test/<nombre>_test.c`. Se puede tomar como molde
   `src/test/buffer_test.c` (define los casos con `START_TEST`/`END_TEST`, los agrupa en una
   `Suite` y corre un `SRunner` en el `main`). Para poder probar funciones internas (`static`)
   se incluye directamente el `.c` bajo prueba, no el `.h`:

   ```c
   #include <check.h>
   #include "modulo.c"   // incluye el .c para acceder a lo interno
   ```

2. **Cablearlo en el `Makefile`.** Agregar el ejecutable a la lista `TESTS` y escribir su regla
   junto a las demás. La regla linkea solo las **dependencias** del test (los `.c` que usa y que
   no estén ya incluidos por el `#include`):

   ```make
   TESTS=... \
         $(TEST_FOLDER)/modulo_test

   $(TEST_FOLDER)/modulo_test: src/test/modulo_test.c src/shared/modulo.c src/shared/dep.c
       mkdir -p $(TEST_FOLDER)
       $(COMPILER) $(COMPILER_FLAGS) src/test/modulo_test.c src/shared/dep.c $(CHECK_FLAGS) -o $@
   ```

   > Ojo: si el test hace `#include "modulo.c"`, **no** hay que volver a pasar `modulo.c` a la
   > línea de `gcc` (daría "multiple definition"); sí se listan sus dependencias (p.ej. `buffer.c`).
   > Los `.c` que se incluyen inline igual se listan como prerequisito (después de los `:`) para
   > que un cambio dispare la recompilación.

3. **Correrlo:** `make test` compila y ejecuta toda la suite; corta con error si alguno falla.

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>

## Instrucciones:

### Servidor Proxy:

```sh
bin/server -a admin:secreto -u alice:pass1
```

> **Importante:** incluir al menos un administrador (`-a <user>:<pass>`) al arrancar.
> Los administradores son los únicos que pueden autenticarse en el servicio de
> monitoreo, y **no pueden crearse en runtime** (`ADD_USER` crea usuarios comunes
> del proxy): un servidor arrancado sin `-a` tiene el monitoreo inutilizable hasta
> reiniciarlo. El servidor arranca igual (con un warning), porque usarlo solo como
> proxy es válido.

Opciones: `-p`/`-l` puerto y dirección del proxy SOCKS (default 1080), `-P`/`-L`
puerto y dirección del monitoreo (default 8080), `-u` usuarios del proxy (hasta 10
entre `-u` y `-a`), `-h` ayuda completa, `-v` versión.

Con el servidor corriendo, cualquier cliente SOCKS5 puede salir a través del
proxy autenticándose con un usuario cargado. Por ejemplo, con `curl`:

```sh
curl --socks5-hostname alice:pass1@127.0.0.1:1080 http://example.com
```

(`--socks5-hostname` delega la resolución DNS en el proxy, que es el caso de uso
típico; con `--socks5` curl resuelve localmente y envía la IP.)

### Cliente de Monitoreo:

El cliente se conecta por defecto al servicio de monitoreo en `127.0.0.1:8080`.
Las credenciales deben pertenecer a un usuario administrador creado con `-a` al
arrancar el servidor.

Modo interactivo (si se omite `-a`, pide usuario y contraseña por terminal):

```sh
bin/client
# o sin prompts de autenticación:
bin/client -a admin:secreto
```

Dentro de la sesión, `help` muestra los comandos disponibles y `quit` la cierra.
Los prompts y errores se escriben en `stderr`; las respuestas del servidor, en
`stdout`, para que se puedan redirigir o procesar desde scripts.

También se puede ejecutar un único comando. En este modo el cliente se autentica,
ejecuta el comando, cierra la sesión y termina:

```sh
bin/client -a admin:secreto stats
bin/client -a admin:secreto config timeout 30
bin/client -a admin:secreto access-log alice
```

Para conectarse a otra dirección o puerto de monitoreo se usan `-L` y `-P`:

```sh
bin/client -L 192.0.2.10 -P 9090 -a admin:secreto stats
```

En modo one-shot, el código de salida es `0` si el servidor respondió `+OK`, `1`
ante un error de autenticación, conexión, protocolo o una respuesta `-ERR`, y `2`
si el comando o los argumentos locales son inválidos.

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>

### Comandos del Cliente de Monitoreo:

| Comando | Descripción |
|---|---|
| `stats` | Muestra métricas globales del proxy. |
| `users` | Lista los usuarios conectados en ese momento. |
| `connections` | Muestra las conexiones actuales y el máximo concurrente. |
| `config <param> <valor>` | Cambia `timeout` (segundos) o `buf_size` (bytes) en runtime. |
| `add-user <user> <pass>` | Agrega un usuario común del proxy. |
| `del-user <user>` | Elimina un usuario del proxy. |
| `access-log [user]` | Muestra el registro de accesos completo o filtrado por usuario. |
| `quit` | Cierra la sesión. |
| `help` | Muestra la ayuda del cliente interactivo. |

Los nombres se aceptan en la forma amigable de la tabla o como comandos del
protocolo (`ADD_USER`, `ACCESS_LOG`, etc.). Los cambios hechos con `config`,
`add-user` y `del-user` viven solo en memoria y se pierden al reiniciar el
servidor. `add-user` crea usuarios comunes: no permite crear administradores.

El contrato completo, incluidos formatos de respuesta, límites y parámetros de
configuración, está en la especificación del protocolo:
[`doc/rfc-monitoreo.md`](doc/rfc-monitoreo.md).

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>

## Limpieza:

Para borrar los binarios y objetos generados en `bin/` y `obj/`:

```sh
make clean
```

Las pruebas end-to-end se documentan en
[`src/test/integration/README.md`](src/test/integration/README.md). La sesión de
monitoreo completa puede ejecutarse con `make integration-test`.

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>

## Estructura:

Materiales del repositorio:

| Ubicación | Contenido |
|---|---|
| `src/server/` | Servidor: proxy SOCKSv5 (`socks5nio.c`, `states/`, `parsers/`) y monitoreo (`mgmt.c`) |
| `src/client/` | Cliente de monitoreo |
| `src/shared/` | Infraestructura común: selector, buffers, máquina de estados, métricas, config |
| `src/test/` | Tests unitarios (`check`) y de integración (`integration/`), más suite de valgrind (`valgrind/`) |
| `doc/` | [Especificación (estilo RFC) del protocolo de monitoreo](doc/rfc-monitoreo.md) |
| `src/docs/` | [Documento de diseño del protocolo de monitoreo](src/docs/monitoring_protocol.md), insumo del RFC |
| `Makefile` / `Makefile.inc` | Build (targets `all`, `server`, `client`, `test`, `integration-test`, `clean`) |

Artefactos generados por `make` (no se versionan):

| Artefacto | Qué es |
|---|---|
| `bin/server` | Servidor proxy SOCKSv5 + servicio de monitoreo |
| `bin/client` | Cliente de monitoreo |
| `bin/test/*` | Binarios de los tests unitarios |
| `obj/` | Objetos intermedios de compilación |

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>

## Integrantes:

* Josefina Ravera (65690) - jravera@itba.edu.ar
* Magalí Gonzalez Porzio (64028) - mgonzalezporzio@itba.edu.ar
* Azul Grelle (65221) - agrelle@itba.edu.ar

<p align="right">(<a href="#tpe---protocolos-de-comunicación">Volver</a>)</p>

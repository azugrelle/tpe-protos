# Protocolo de Monitoreo — Diseño 

## 1. Descripción general

Protocolo de texto orientado a línea, sobre TCP, en un socket pasivo independiente del
proxy SOCKS5. Dirección y puerto se configuran vía `args.h`: **`-L` fija la dirección**
(`mng_addr`) y **`-P` fija el puerto** (`mng_port`). Permite a un administrador consultar
métricas, gestionar usuarios, configurar parámetros en runtime y consultar el access log.

## 2. Framing

- Cada comando y cada respuesta es una línea de texto terminada en `\n`. Se tolera y
  descarta un `\r` final si llega (compatibilidad con clientes que mandan `\r\n`, como
  `telnet` o algunos `nc`).
- Longitud máxima de línea: **512 bytes**. Líneas más largas se rechazan con
  `-ERR line too long` y se cierra la conexión.
- Codificación: ASCII.
- Tokenización: los campos de un comando se separan por **un único espacio** (`' '`). El
  **último argumento es el resto de la línea tal cual, a partir del primer espacio
  separador** (sin recortar ni agregar espacios) — esto permite passwords con espacios
  en `AUTH`/`ADD_USER` sin ambigüedad.
- Los nombres de comando usan únicamente `A-Z 0-9 _`, son **case-sensitive** (se esperan
  en mayúsculas: `STATS`, no `stats`). Los **usernames también son case-sensitive**
  (`alice` ≠ `Alice`), largo entre 1 y 255 caracteres, charset `a-z A-Z 0-9 _`.

## 3. Autenticación

> ⚠️ **Decisión de seguridad:** el monitoreo **no** reutiliza la tabla de usuarios del
> proxy SOCKS tal cual. Se agrega un flag `is_admin` al `struct users` de `args.h`. Solo
> los usuarios con `is_admin = true` pueden autenticarse en el puerto de monitoreo. Un
> usuario común del proxy (sin ese flag) recibe `-ERR invalid credentials` aunque su
> user/pass sea correcto para SOCKS.

```
S: +OK monitor ready
C: AUTH <user> <pass>
S: +OK authenticated
   (o)
S: -ERR invalid credentials
```

Hasta autenticarse, el servidor solo acepta `AUTH` o `QUIT`; cualquier otro comando
responde `-ERR not authenticated`.

Si el cliente envía `AUTH` estando ya autenticado, el servidor responde
`-ERR already authenticated` (no se permite reautenticar ni cambiar de usuario a mitad
de sesión).

> ⚠️ **Limitación conocida:** las credenciales viajan en texto plano. No se cifra el
> canal. Se documenta como simplificación aceptada para el alcance del TPE.

## 4. Formato de respuesta

**Una línea** (éxito/error simple):
```
+OK <mensaje opcional>
-ERR <motivo>
```
Los errores son **siempre de una sola línea** — nunca aparecen a mitad de una respuesta
multilínea.

**Multilínea** (listas: STATS, USERS, CONNECTIONS, ACCESS_LOG), terminada con un punto
solo en su línea, sin indentación:
```
+OK
<línea 1>
<línea 2>
.
```
Si la lista está vacía:
```
+OK
.
```

## 5. Errores genéricos (aplican a cualquier comando)

| Situación | Respuesta |
|---|---|
| Token no matchea ningún comando conocido | `-ERR unknown command` |
| Comando reconocido con cantidad o formato de argumentos incorrecto (ej. `AUTH` con un solo token, `CONFIG` sin valor, `DEL_USER` sin argumento) | `-ERR invalid arguments` |
| Comando antes de autenticarse (salvo `AUTH`/`QUIT`) | `-ERR not authenticated` |

## 6. Comandos

| Comando | Sintaxis | Respuesta |
|---|---|---|
| `STATS` | `STATS` | multilínea: `historical_connections: N`, `concurrent_connections: N`, `max_concurrent: N`, `active_users: N`, `bytes_transferred: N`, `uptime: N` (segundos) |
| `USERS` | `USERS` | multilínea: una línea por usuario **activo** (conectado ahora), solo el nombre — nunca contraseñas |
| `CONNECTIONS` | `CONNECTIONS` | multilínea: conteos agregados `current_connections: N` y `max_concurrent: N`. No hay detalle por conexión (origen/destino): exigiría registrar esos datos por conexión activa en el camino del relay; ver el registro de decisiones |
| `CONFIG` | `CONFIG <param> <valor>` | `+OK` / `-ERR unknown param` / `-ERR invalid value` |
| `ADD_USER` | `ADD_USER <user> <pass>` | `+OK` / `-ERR user exists` / `-ERR user table full` |
| `DEL_USER` | `DEL_USER <user>` | `+OK` / `-ERR user not found` / `-ERR cannot delete last admin` |
| `ACCESS_LOG` | `ACCESS_LOG` o `ACCESS_LOG <user>` | multilínea: `<user> <domain>:<port> <timestamp> <status>` por línea |
| `QUIT` | `QUIT` | `+OK bye` y cierra la conexión |

### Parámetros válidos de `CONFIG`
- `timeout`: entero positivo, en segundos, máximo 86400 (24h). Valor fuera de rango o no
  numérico → `-ERR invalid value`. Aplica **solo a conexiones nuevas**.
- `buf_size`: entero positivo, en bytes, máximo 1048576 (1 MiB). Mismas reglas de
  validación. Aplica **solo a conexiones nuevas** (cambiar el tamaño de un buffer ya en
  uso por una conexión activa no es trivial con la infraestructura provista).

### Límite de usuarios
`MAX_USERS` está definido en `args.h` (10). `ADD_USER` sobre la tabla llena devuelve
`-ERR user table full`.

### Protección del último admin
`DEL_USER` sobre el **único** usuario con `is_admin = true` devuelve
`-ERR cannot delete last admin` — evita quedar sin forma de volver a entrar al
monitoreo hasta reiniciar el proceso.

### Persistencia
`ADD_USER`, `DEL_USER` y `CONFIG` son **solo en memoria**: no persisten a disco ni
sobreviven un reinicio del proceso.

## 7. Formato de `ACCESS_LOG`

```
<user> <domain>:<port> <timestamp> <status>
```
- `timestamp`: ISO 8601, `YYYY-MM-DDThh:mm:ssZ` (UTC).
- `status`: `SUCCESS` o `FAIL`.

Ejemplo:
```
alice www.google.com:80 2025-07-15T01:29:41Z SUCCESS
```

## 8. Ejemplo de sesión completa

```
S: +OK monitor ready
C: AUTH alice secret123
S: +OK authenticated
C: STATS
S: +OK
historical_connections: 42
concurrent_connections: 3
max_concurrent: 10
active_users: 2
bytes_transferred: 198234
uptime: 3601
.
C: ADD_USER bob hunter2
S: +OK
C: CONFIG timeout 30
S: +OK
C: CONFIG timeout abc
S: -ERR invalid value
C: ACCESS_LOG bob
S: +OK
.
C: FOO
S: -ERR unknown command
C: QUIT
S: +OK bye
[conexión cerrada]
```

## 9. Notas de implementación

- Este protocolo corre como un segundo socket pasivo registrado en el mismo
  `selector.c`, con su propia máquina de estados (independiente de la STM de SOCKS5),
  usando la misma infraestructura de `buffer.c`/`stm.c`/`parser.c` provista por la
  cátedra.
- Este documento es el insumo directo de T32 (implementación del handler) y de T100
  (formalización como RFC).
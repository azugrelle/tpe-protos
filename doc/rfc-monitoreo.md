# Protocolo de Monitoreo y Administración del Proxy SOCKSv5 (MMP)

```
Grupo 22 — ITBA, Protocolos de Comunicación 2026/1
Categoría: Especificación de protocolo
Estado: Borrador para el TPE
```

## Resumen

Este documento especifica el Protocolo de Monitoreo y Administración (en
adelante, "el protocolo"): un protocolo de texto orientado a línea, sobre TCP,
que permite a un administrador consultar métricas de un servidor proxy SOCKSv5,
gestionar sus usuarios, ajustar parámetros de configuración en tiempo de
ejecución y consultar el registro de accesos. La especificación es completa y
autocontenida: un cliente o servidor conforme puede implementarse en cualquier
lenguaje leyendo únicamente este documento.

---

## 1. Introducción y alcance

El protocolo corre sobre TCP, en un socket pasivo **independiente** del que
atiende el tráfico SOCKSv5. El servidor de monitoreo y el proxy SOCKS son dos
servicios del mismo proceso: el monitoreo observa y administra el estado del
proxy (métricas, tabla de usuarios, parámetros, registro de accesos), pero el
tráfico de los clientes SOCKS nunca pasa por este canal.

La dirección y el puerto de escucha se fijan operativamente al lanzar el
servidor (en la implementación de referencia, con las opciones `-L` dirección y
`-P` puerto; por defecto `127.0.0.1:8080`).

Este documento NO cubre:

- el protocolo SOCKS versión 5 ([RFC 1928]) ni su subnegociación de
  autenticación ([RFC 1929]); solo se lo referencia como el servicio
  monitoreado;
- la interfaz de línea de comandos del servidor;
- persistencia: todo cambio hecho por este protocolo (usuarios, configuración)
  vive solo en memoria y se pierde al reiniciar el proceso (ver §8.5, §8.6).

## 2. Lenguaje de requisitos

Las palabras clave "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY" y "OPTIONAL" en este documento
deben interpretarse como se describe en BCP 14 [RFC 2119] [RFC 8174] cuando, y
solo cuando, aparecen en mayúsculas como aquí.

## 3. Terminología

- **Servidor**: el extremo que escucha en el socket pasivo de monitoreo y
  ejecuta los comandos.
- **Cliente**: el extremo que se conecta y envía comandos.
- **Administrador (admin)**: usuario de la tabla de usuarios del proxy marcado
  con el atributo de administrador. Solo los administradores pueden
  autenticarse en este protocolo (§6). El atributo de administrador solo puede
  otorgarse al lanzar el servidor; no existe comando para crearlo o cambiarlo
  en runtime.
- **Sesión**: el lapso de vida de una conexión TCP contra el servidor. El
  estado de autenticación y el contador de intentos fallidos son por sesión.
- **Comando**: una línea enviada por el cliente (§5).
- **Respuesta simple**: respuesta de exactamente una línea, `+OK ...` o
  `-ERR ...` (§7.1).
- **Respuesta multilínea**: respuesta compuesta por una línea `+OK`, cero o más
  líneas de datos y una línea terminadora `.` (§7.2).
- **Usuario activo**: usuario con al menos una conexión SOCKS abierta en este
  momento.

## 4. Modelo de conexión

1. El protocolo corre sobre TCP. Cada conexión TCP es una sesión independiente;
   no hay estado compartido entre sesiones (más allá del estado global del
   proxy que los comandos consultan o modifican).
2. **El servidor habla primero**: inmediatamente después de aceptar la
   conexión, el servidor MUST enviar el saludo, exactamente:

   ```
   +OK monitor ready
   ```

   Excepción: el servidor MAY imponer un límite a la cantidad de sesiones de
   monitoreo simultáneas (16 en la implementación de referencia; ver §12). Con
   el cupo lleno, MAY responder **en lugar del saludo**

   ```
   -ERR too many sessions
   ```

   y cerrar la conexión. Un cliente conforme MUST tratar una primera línea
   `-ERR ...` como rechazo de la conexión y MUST NOT enviar credenciales.

3. Toda sesión comienza en estado **no autenticado** (§6).
4. A partir del saludo el protocolo es estrictamente de tipo pedido/respuesta:
   cada línea de comando del cliente produce exactamente una respuesta (simple
   o multilínea). El servidor MUST responder los comandos en el mismo orden en
   que los recibió. El cliente MAY enviar varios comandos sin esperar las
   respuestas (*pipelining*); el servidor MAY demorar la lectura de nuevos
   comandos mientras tenga respuestas pendientes de entregar (control de
   flujo), lo cual es invisible en el protocolo.
5. La sesión termina cuando:
   - el cliente envía `QUIT` (§8.9): el servidor responde `+OK bye`, termina de
     transmitir todo lo pendiente y cierra la conexión;
   - el cliente agota los intentos de autenticación (§6.3): el servidor
     responde `-ERR too many failed logins` y cierra;
   - el cliente envía una línea que excede el largo máximo (§5.2): el servidor
     responde `-ERR line too long` y cierra;
   - el servidor la cierra por **inactividad**: el servidor MAY cerrar, sin
     emitir respuesta alguna, una sesión sin actividad de E/S durante un
     tiempo. Se RECOMIENDA un umbral corto para las sesiones no autenticadas,
     que un cliente puede abrir sin acreditar identidad (la implementación de
     referencia usa 30 segundos sin autenticar y 600 segundos autenticada);
   - el cliente cierra la conexión, o se produce un error de E/S.

   En los casos de cierre iniciado por el servidor que llevan respuesta
   (`QUIT`, intentos agotados, línea excesiva), este MUST transmitir la
   respuesta completa antes de cerrar, y MUST NOT procesar comandos
   adicionales que hubieran quedado en vuelo (se descartan sin respuesta). El
   cierre por inactividad no lleva respuesta.

## 5. Framing y sintaxis léxica

### 5.1 Líneas

La unidad de intercambio en ambas direcciones es la **línea**: una secuencia de
octetos terminada en LF (`%x0A`).

- El cliente SHOULD terminar sus líneas con LF a secas. El servidor MUST
  tolerar el terminador CRLF: si el octeto inmediatamente anterior al LF es CR
  (`%x0D`), el servidor MUST descartar ese CR (compatibilidad con clientes como
  `telnet`). Solo se descarta **un** CR, y solo en esa posición; un CR en
  cualquier otra parte de la línea es contenido.
- El servidor termina todas sus líneas con LF a secas (MUST NOT emitir CRLF).
- Codificación: US-ASCII. Los emisores MUST NOT enviar octetos fuera del rango
  `%x20-7E` en el contenido de una línea (véase la nota de §5.4 sobre
  contraseñas).

### 5.2 Largo máximo de línea

Una línea de comando, incluido su LF final (y el CR opcional), MUST NOT exceder
**512 octetos** (es decir, hasta 511 octetos de contenido). Ante una línea más
larga el servidor MUST responder

```
-ERR line too long
```

y cerrar la conexión (§4.5).

Las líneas de **respuesta** del servidor pueden ser más largas que las de
comando: el servidor MUST NOT emitir líneas de más de **600 octetos** incluido
el LF, y un cliente conforme MUST aceptar líneas de respuesta de hasta ese
largo.

### 5.3 Tokenización de un comando

- El nombre de comando es la secuencia de octetos desde el comienzo de la línea
  hasta el primer SP (`%x20`) exclusive, o hasta el fin de línea si no hay SP.
- Los nombres de comando son **case-sensitive** y MUST enviarse exactamente
  como figuran en §8 (mayúsculas): `stats` o `Stats` no son `STATS` y producen
  `-ERR unknown command`.
- Los argumentos se separan entre sí por **exactamente un** SP. No se admite
  otro espaciado (varios SP seguidos, tabulaciones) ni espacio al final de la
  línea; el efecto de esos octetos es formar parte del argumento que toque, y
  en general provoca `-ERR invalid arguments` o un fallo semántico.
- **Regla del último argumento**: el último argumento de un comando es *el
  resto de la línea tal cual*, desde el octeto siguiente al SP separador hasta
  el fin de línea, sin recortar ni normalizar. Esto permite contraseñas que
  contienen SP en `AUTH` y `ADD_USER` sin ambigüedad ni comillas.

### 5.4 Gramática (ABNF)

La gramática usa la notación ABNF de [RFC 5234], incluidas sus reglas núcleo
(`ALPHA`, `DIGIT`, `SP`, `CR`, `LF`).

```abnf
; ---- léxico común ----
eol-in    = [CR] LF          ; terminador aceptado por el servidor
eol-out   = LF               ; terminador emitido por el servidor
PRINT     = %x20-7E          ; US-ASCII imprimible, incluye SP

username  = 1*255uchar
uchar     = ALPHA / DIGIT / "_"
password  = 1*255PRINT       ; puede contener SP (regla del último argumento)
number    = "0" / ( %x31-39 *DIGIT )   ; decimal sin signo, sin ceros a la izq.

; ---- línea de comando ----
command-line   = command eol-in

command        = cmd-auth / cmd-quit / cmd-stats / cmd-users
               / cmd-connections / cmd-config / cmd-add-user
               / cmd-del-user / cmd-access-log

cmd-auth       = %s"AUTH" SP username SP password
cmd-quit       = %s"QUIT"
cmd-stats      = %s"STATS"
cmd-users      = %s"USERS"
cmd-connections = %s"CONNECTIONS"
cmd-config     = %s"CONFIG" SP param SP param-value
param          = %s"timeout" / %s"buf_size"
param-value    = 1*DIGIT     ; validación de rango en §8.4
cmd-add-user   = %s"ADD_USER" SP username SP password
cmd-del-user   = %s"DEL_USER" SP username
cmd-access-log = %s"ACCESS_LOG" [SP username]

; ---- respuestas ----
response        = simple-ok / error-line / multi-response

simple-ok       = %s"+OK" [SP text] eol-out
error-line      = %s"-ERR" SP text eol-out
text            = 1*PRINT

multi-response  = %s"+OK" eol-out *data-line terminator
data-line       = 1*599PRINT eol-out   ; nunca coincide con "." (§7.2)
terminator      = "." eol-out
```

(`%s"..."` denota literal case-sensitive, [RFC 7405].)

Notas:

- `username`: entre 1 y 255 octetos del conjunto `A-Z a-z 0-9 _`. Los
  usernames son **case-sensitive** (`alice` ≠ `Alice`).
- `password`: entre 1 y 255 octetos. Al ser siempre el último argumento, puede
  contener SP. Esta especificación exige US-ASCII imprimible; el
  comportamiento con otros octetos queda sin especificar.
- `param-value` admite ceros a la izquierda (`030` = 30); el valor cero se
  rechaza siempre (§8.4).

### 5.5 Precedencia de la validación

Al recibir una línea de comando el servidor MUST aplicar las verificaciones en
este orden, respondiendo con el primer error que corresponda:

1. **Largo**: línea de más de 512 octetos → `-ERR line too long` y cierre
   (§5.2).
2. **Comando conocido**: el primer token no es exactamente uno de los nueve
   nombres de §8 (esto incluye la línea vacía, minúsculas, y cualquier otro
   token) → `-ERR unknown command`. La conexión permanece abierta.
3. **Autenticación**: el comando exige sesión autenticada y la sesión no lo
   está → `-ERR not authenticated` (§6.1). Este paso precede a la validación
   de argumentos: un `STATS extra` sin autenticar produce
   `-ERR not authenticated`, no `-ERR invalid arguments`.
4. **Validación propia del comando**: argumentos y semántica, según §8. Para
   `AUTH`, la condición "ya autenticado" precede a la validación de argumentos
   (§6.2).

## 6. Autenticación

### 6.1 Estado no autenticado

Toda sesión nace no autenticada. En ese estado el servidor MUST aceptar
únicamente `AUTH` y `QUIT`; ante cualquier otro comando reconocido MUST
responder:

```
-ERR not authenticated
```

### 6.2 El comando AUTH

```
C: AUTH <username> <password>
```

El servidor valida las credenciales contra la tabla de usuarios del proxy, pero
MUST aceptar únicamente usuarios con el atributo de **administrador** (§3). Un
usuario común del proxy —credenciales correctas para SOCKS, sin el atributo—
MUST recibir exactamente la misma respuesta que un usuario inexistente o una
contraseña incorrecta, para no filtrar qué usuarios existen ni cuáles son
administradores:

```
-ERR invalid credentials
```

Con credenciales de administrador válidas el servidor responde:

```
+OK authenticated
```

y la sesión pasa al estado autenticado, donde permanece hasta cerrarse.

Reglas adicionales:

- **Reautenticación**: si la sesión ya está autenticada, `AUTH` (con o sin
  argumentos, válidos o no) MUST responder `-ERR already authenticated`. No se
  permite reautenticar ni cambiar de usuario dentro de una sesión.
- **Sintaxis**: `AUTH` sin argumentos, con un solo token, o con `username`
  vacío (dos SP seguidos) MUST responder `-ERR invalid arguments`.
- **Contraseña vacía**: una línea `AUTH <username> ` (SP final, resto vacío)
  es sintácticamente válida —la contraseña es el resto de la línea, que
  resulta vacío— y se procesa como una verificación de credenciales, que
  falla: responde `-ERR invalid credentials` y consume un intento (§6.3).

### 6.3 Límite de intentos fallidos

El servidor MUST llevar, por sesión, un contador de intentos de `AUTH` con
credenciales inválidas. Al **tercer** fallo el servidor MUST responder

```
-ERR too many failed logins
```

(en lugar de `-ERR invalid credentials`) y cerrar la conexión (§4.5). Este es
el freno a la fuerza bruta sobre un canal en texto plano (§12): reconectar
renueva el cupo, al costo de un establecimiento TCP por cada tanda de tres.

Los errores de sintaxis (`-ERR invalid arguments`) y `-ERR already
authenticated` MUST NOT consumir intentos.

## 7. Formato de respuestas

### 7.1 Respuesta simple

Una única línea:

```
+OK [<texto opcional>]
-ERR <motivo>
```

### 7.2 Respuesta multilínea

```
+OK
<línea de datos 1>
...
<línea de datos N>
.
```

- La primera línea es `+OK` **a secas** (sin texto adicional).
- Siguen cero o más líneas de datos.
- Cierra una línea que contiene únicamente `.` (un punto, sin indentación).
- Lista vacía: `+OK` seguido inmediatamente de `.`.

Por construcción ninguna línea de datos de este protocolo puede consistir en un
`.` solo (los usernames no admiten `.` y las demás líneas de datos empiezan con
un nombre de campo o un username), de modo que el terminador no necesita
escape. Un servidor conforme MUST garantizar esta propiedad si extiende el
protocolo.

### 7.3 Invariante de framing

**El formato de la respuesta exitosa lo determina el comando, no el
contenido**:

- `STATS`, `USERS`, `CONNECTIONS` y `ACCESS_LOG` responden éxito **siempre** en
  formato multilínea, aun con lista vacía. MUST NOT degenerar en un
  `+OK <texto>` de una sola línea.
- Todos los demás comandos (`AUTH`, `CONFIG`, `ADD_USER`, `DEL_USER`, `QUIT`)
  responden éxito **siempre** en una sola línea.
- Los errores (`-ERR ...`) son **siempre** de una sola línea, para cualquier
  comando. Un error MUST NOT aparecer dentro de una respuesta multilínea: si un
  comando de lista falla, falla antes de emitir el `+OK` inicial.

Consecuencia para el cliente: sabiendo qué comando envió y leyendo el primer
token de la primera línea de respuesta (`+OK` o `-ERR`), el cliente decide sin
heurísticas si debe leer una línea o hasta el `.` terminador.

## 8. Comandos

Salvo indicación contraria, todos los comandos requieren sesión autenticada
(§6.1). `AUTH` y `QUIT` son los únicos disponibles sin autenticar.

Los comandos que se definen **sin argumentos** (`STATS`, `USERS`,
`CONNECTIONS`, `QUIT`) MUST rechazarse con `-ERR invalid arguments` si la línea
contiene cualquier cosa después del nombre (incluso un SP final).

### 8.1 AUTH — autenticación

Definido en §6.

| Error | Condición |
|---|---|
| `-ERR already authenticated` | la sesión ya está autenticada (precede a todo otro chequeo de `AUTH`) |
| `-ERR invalid arguments` | falta algún argumento, o `username` vacío |
| `-ERR invalid credentials` | usuario inexistente, contraseña incorrecta, o usuario sin atributo de administrador |
| `-ERR too many failed logins` | tercer fallo de credenciales en la sesión; el servidor cierra la conexión |

### 8.2 STATS — métricas globales

```
C: STATS
```

Respuesta multilínea con exactamente seis líneas de datos, en este orden, con
el formato `<campo>: <valor>` (dos puntos y un SP):

```abnf
stats-data = %s"historical_connections: " number eol-out
             %s"concurrent_connections: " number eol-out
             %s"max_concurrent: " number eol-out
             %s"active_users: " number eol-out
             %s"bytes_transferred: " number eol-out
             %s"uptime: " number eol-out
```

| Campo | Semántica |
|---|---|
| `historical_connections` | conexiones SOCKS aceptadas desde el arranque del servidor |
| `concurrent_connections` | conexiones SOCKS abiertas en este momento |
| `max_concurrent` | máximo histórico de conexiones simultáneas |
| `active_users` | cantidad de usuarios activos (§3) en este momento |
| `bytes_transferred` | total de octetos retransmitidos por el proxy (ambos sentidos sumados) desde el arranque |
| `uptime` | segundos transcurridos desde el arranque del servidor |

Los valores son enteros decimales sin signo; los contadores son de al menos 64
bits y un cliente MUST tolerar valores de hasta 20 dígitos.

| Error | Condición |
|---|---|
| `-ERR not authenticated` | sesión sin autenticar |
| `-ERR invalid arguments` | la línea trae algo después de `STATS` |

### 8.3 USERS — usuarios activos

```
C: USERS
```

Respuesta multilínea: una línea de datos por usuario **activo** (§3),
conteniendo únicamente el `username`. La respuesta MUST NOT incluir
contraseñas ni ningún otro atributo. Usuarios existentes pero sin conexiones
abiertas no aparecen. Varias conexiones simultáneas del mismo usuario producen
una sola línea. El orden de las líneas no está especificado.

La cantidad de líneas está acotada por el tamaño de la tabla de usuarios
(§8.5): a lo sumo 10.

| Error | Condición |
|---|---|
| `-ERR not authenticated` | sesión sin autenticar |
| `-ERR invalid arguments` | la línea trae algo después de `USERS` |

### 8.4 CONNECTIONS — conteos de conexiones

```
C: CONNECTIONS
```

Respuesta multilínea con exactamente dos líneas de datos, en este orden:

```abnf
connections-data = %s"current_connections: " number eol-out
                   %s"max_concurrent: " number eol-out
```

`current_connections` coincide con `concurrent_connections` de `STATS`;
`max_concurrent` es el mismo pico histórico. Este protocolo no expone detalle
por conexión (origen/destino).

| Error | Condición |
|---|---|
| `-ERR not authenticated` | sesión sin autenticar |
| `-ERR invalid arguments` | la línea trae algo después de `CONNECTIONS` |

### 8.5 CONFIG — parámetros en runtime

```
C: CONFIG <param> <valor>
```

Ajusta un parámetro operativo del proxy. Respuesta de éxito: `+OK` (una línea).
Los cambios son **solo en memoria**: no persisten a un reinicio del proceso.

El `<valor>` MUST ser un entero decimal sin signo compuesto solo por dígitos
ASCII: sin signo (`+30`, `-1`), sin espacios, sin sufijos (`30abc`) ni parte
fraccionaria. Se admiten ceros a la izquierda (`030` = 30). El valor cero se
rechaza siempre.

Parámetros definidos:

| Parámetro | Rango | Semántica |
|---|---|---|
| `timeout` | 1 – 86400 (segundos) | umbral de inactividad tras el cual el proxy cierra una conexión SOCKS. Aplica a **todas** las conexiones, nuevas y ya activas: el umbral se reevalúa periódicamente (granularidad ~1 s), de modo que un cambio afecta a las conexiones vivas en la siguiente evaluación. Valor por defecto: 300. |
| `buf_size` | 22 – 1048576 (octetos) | tamaño de los buffers de E/S de una conexión del proxy. Aplica **solo a conexiones nuevas**; las vivas conservan el tamaño con el que nacieron. El mínimo de 22 es el tamaño de la mayor respuesta SOCKS que el proxy serializa entera (reply del REQUEST con BND.ADDR IPv6); por debajo, toda conexión nueva fallaría al responder. Por rendimiento se RECOMIENDA no bajar de ~512. Valor por defecto: 2048. |

La validación es en dos pasos y en este orden: primero el nombre del parámetro,
después el valor. `CONFIG foo 30` produce `-ERR unknown param`, no
`-ERR invalid value`.

| Error | Condición |
|---|---|
| `-ERR not authenticated` | sesión sin autenticar |
| `-ERR invalid arguments` | faltan tokens, o `<param>`/`<valor>` vacíos. Nota: `CONFIG timeout 30 40` no es este error — el tercer token queda dentro de `<valor>` (regla del último argumento, §5.3) y produce `-ERR invalid value` |
| `-ERR unknown param` | `<param>` no es `timeout` ni `buf_size` (case-sensitive) |
| `-ERR invalid value` | `<valor>` no es un entero decimal puro, es cero, o está fuera del rango del parámetro |

### 8.6 ADD_USER — alta de usuario

```
C: ADD_USER <username> <password>
```

Crea un usuario del proxy SOCKS en runtime. El usuario creado MUST ser un
usuario **común** (sin atributo de administrador): este protocolo no permite
crear administradores (§3). Respuesta de éxito: `+OK` (una línea). El alta es
solo en memoria (no persiste).

`<username>` MUST cumplir la regla `username` de §5.4 (1–255 octetos de
`A-Z a-z 0-9 _`). `<password>` es el resto de la línea (puede contener SP) y
MUST tener entre 1 y 255 octetos.

La tabla de usuarios tiene capacidad para **10** usuarios en total,
compartida entre los usuarios dados de alta al lanzar el servidor y los creados
por este comando.

| Error | Condición |
|---|---|
| `-ERR not authenticated` | sesión sin autenticar |
| `-ERR invalid arguments` | faltan tokens; `username` vacío o con octetos fuera de su charset o de más de 255 octetos; `password` vacío o de más de 255 octetos |
| `-ERR user exists` | ya hay un usuario con ese nombre (comparación exacta, case-sensitive). Este chequeo precede al de tabla llena |
| `-ERR user table full` | la tabla ya tiene 10 usuarios |

### 8.7 DEL_USER — baja de usuario

```
C: DEL_USER <username>
```

Elimina un usuario de la tabla. Respuesta de éxito: `+OK` (una línea). La baja
es solo en memoria (no persiste).

**Protección del último administrador**: si `<username>` es el único usuario
con atributo de administrador, el servidor MUST rechazar la baja con
`-ERR cannot delete last admin`; de lo contrario el sistema quedaría sin acceso
al monitoreo hasta reiniciar el proceso. Un administrador sí puede eliminarse
(incluso a sí mismo) mientras exista al menos otro administrador; la sesión en
curso no se ve afectada (la autenticación es por sesión, §6.2).

| Error | Condición |
|---|---|
| `-ERR not authenticated` | sesión sin autenticar |
| `-ERR invalid arguments` | falta el argumento o está vacío |
| `-ERR user not found` | no existe un usuario con ese nombre exacto. Nota: como el argumento es el resto de la línea (§5.3), un argumento con SP interno nunca matchea un username válido y produce este error |
| `-ERR cannot delete last admin` | el usuario es el único administrador |

### 8.8 ACCESS_LOG — registro de accesos

```
C: ACCESS_LOG
C: ACCESS_LOG <username>
```

Devuelve, en formato multilínea, el registro de accesos (destinos solicitados a
través del proxy): completo, o filtrado por un usuario. El formato de cada
línea de datos, la retención y el orden se especifican en §10.

Un `<username>` sin accesos registrados —incluido uno que no existe— produce
una lista vacía (`+OK` y `.`), **no** un error: el comando no revela si un
usuario existe.

| Error | Condición |
|---|---|
| `-ERR not authenticated` | sesión sin autenticar |
| `-ERR invalid arguments` | argumento vacío (SP final) o más de un argumento (SP dentro del resto de la línea) |
| `-ERR internal error` | el servidor no pudo materializar la respuesta (agotamiento de recursos). No indica un problema con el comando; el cliente MAY reintentar |

### 8.9 QUIT — cierre ordenado

```
C: QUIT
```

Disponible con o sin autenticación. El servidor responde

```
+OK bye
```

y cierra la conexión una vez transmitida la despedida completa (§4.5).

| Error | Condición |
|---|---|
| `-ERR invalid arguments` | la línea trae algo después de `QUIT` (la sesión continúa) |

## 9. Tabla consolidada de errores

Texto exacto de cada error (el contenido completo de la línea, tras el cual va
el LF), y cuándo ocurre. "Cierra" indica que el servidor cierra la conexión
después de transmitir el error.

| Respuesta | Comandos | Condición | Cierra |
|---|---|---|---|
| `-ERR too many sessions` | (al conectar) | límite de sesiones simultáneas alcanzado; se emite en lugar del saludo (§4) | sí |
| `-ERR line too long` | (cualquier línea) | línea de comando de más de 512 octetos (§5.2) | sí |
| `-ERR unknown command` | (cualquier línea) | el primer token no es un comando (incluye línea vacía y errores de mayúsculas) | no |
| `-ERR not authenticated` | todos salvo `AUTH`, `QUIT` | sesión sin autenticar | no |
| `-ERR already authenticated` | `AUTH` | sesión ya autenticada | no |
| `-ERR invalid arguments` | todos | cantidad o formato de argumentos inválido (ver cada comando) | no |
| `-ERR invalid credentials` | `AUTH` | credenciales incorrectas o usuario sin atributo de administrador | no |
| `-ERR too many failed logins` | `AUTH` | tercer fallo de credenciales en la sesión (§6.3) | sí |
| `-ERR unknown param` | `CONFIG` | parámetro inexistente | no |
| `-ERR invalid value` | `CONFIG` | valor no numérico, cero o fuera de rango | no |
| `-ERR user exists` | `ADD_USER` | el username ya está en la tabla | no |
| `-ERR user table full` | `ADD_USER` | tabla de usuarios llena (10) | no |
| `-ERR user not found` | `DEL_USER` | username inexistente | no |
| `-ERR cannot delete last admin` | `DEL_USER` | el usuario es el único administrador | no |
| `-ERR internal error` | `ACCESS_LOG` | agotamiento de recursos del servidor | no |

Un cliente MUST tratar cualquier línea `-ERR <texto>` no listada como un error
genérico de una línea (§7.3): el conjunto de motivos puede crecer en versiones
futuras sin romper el framing.

## 10. Formato del registro de accesos

Cada línea de datos de `ACCESS_LOG` tiene el formato:

```
<username> <host>:<port> <timestamp> <status>
```

```abnf
log-line  = username SP dest SP timestamp SP status
dest      = host ":" port
host      = 1*(%x21-7E)      ; nombre de dominio o dirección IP literal
port      = 1*5DIGIT
timestamp = date %s"T" time %s"Z"
date      = 4DIGIT "-" 2DIGIT "-" 2DIGIT     ; YYYY-MM-DD
time      = 2DIGIT ":" 2DIGIT ":" 2DIGIT     ; hh:mm:ss
status    = %s"SUCCESS" / %s"FAIL"
```

- Los cuatro campos se separan por un único SP. Ni `username` ni `host` pueden
  contener SP.
- `host` es el destino tal como lo pidió el cliente SOCKS: un nombre de
  dominio o una dirección IP literal. Una dirección IPv6 literal contiene `:`,
  de modo que para separar `host` de `port` el cliente MUST partir en el
  **último** `:` de `dest`.
- `timestamp` es ISO 8601 en UTC, con precisión de segundos y sufijo `Z`:
  `YYYY-MM-DDThh:mm:ssZ`.
- `status` es `SUCCESS` si el proxy estableció la conexión al destino, `FAIL`
  si el intento falló (cualquiera sea la causa).

Ejemplo:

```
alice www.google.com:80 2026-07-15T01:29:41Z SUCCESS
```

**Retención**: el registro es volátil (se pierde al reiniciar) y el servidor
conserva a lo sumo las **últimas 512 visitas por usuario**; al superarse ese
tope se descartan las más antiguas de ese usuario. Se descarta lo viejo y no lo
nuevo porque el caso de uso es investigar accesos recientes.

**Orden**: las líneas salen **agrupadas por usuario** (todos los accesos de un
usuario, contiguos), en orden **cronológico ascendente dentro de cada usuario**
(del más antiguo retenido al más reciente). El orden entre usuarios no está
especificado; en particular NO hay orden cronológico global.

**Consistencia**: la respuesta es una fotografía del registro al momento de
despachar el comando; los accesos que ocurran durante la transmisión aparecen
recién en la próxima consulta.

## 11. Ejemplo de sesión completa

`C:` es el cliente, `S:` el servidor. Cada línea termina en LF.

```
S: +OK monitor ready              ; saludo: el servidor habla primero (§4)
C: STATS
S: -ERR not authenticated         ; sin autenticar solo AUTH/QUIT (§6.1)
C: AUTH alice wrongpass
S: -ERR invalid credentials       ; consume 1 de 3 intentos (§6.3)
C: AUTH alice secret123
S: +OK authenticated              ; la sesión queda autenticada
C: STATS
S: +OK                            ; multilínea: +OK a secas (§7.2)
S: historical_connections: 42
S: concurrent_connections: 3
S: max_concurrent: 10
S: active_users: 2
S: bytes_transferred: 198234
S: uptime: 3601
S: .                              ; terminador
C: ADD_USER bob hunter2
S: +OK                            ; simple: una sola línea (§7.3)
C: CONFIG timeout 30
S: +OK
C: CONFIG timeout abc
S: -ERR invalid value
C: ACCESS_LOG alice
S: +OK
S: alice www.google.com:80 2026-07-15T01:29:41Z SUCCESS
S: alice example.org:443 2026-07-15T01:30:02Z FAIL
S: .
C: ACCESS_LOG bob
S: +OK                            ; usuario sin accesos: lista vacía, no error
S: .
C: FOO
S: -ERR unknown command
C: QUIT
S: +OK bye
   [el servidor cierra la conexión]
```

## 12. Security Considerations

Este protocolo se diseñó para el alcance de un trabajo práctico y asume que
corre en un entorno controlado. Limitaciones y mitigaciones:

- **Credenciales en texto plano, canal sin cifrar.** `AUTH` y `ADD_USER`
  transmiten contraseñas en claro y ninguna parte del diálogo va cifrada ni
  autenticada a nivel de canal. Cualquier observador de la red puede capturar
  credenciales de administrador y todo el contenido (incluido el historial de
  navegación que expone `ACCESS_LOG`). Se asume como simplificación aceptada;
  en un despliegue real el servicio debería ir detrás de TLS o de un túnel
  seguro. Mitigación operativa: por defecto el servicio escucha solo en
  `127.0.0.1`, y se RECOMIENDA no exponerlo fuera del host o de una red de
  administración.
- **Fuerza bruta.** El límite de tres fallos de `AUTH` por sesión (§6.3)
  obliga a pagar un establecimiento TCP por cada tres intentos. Es un freno,
  no una defensa completa: no hay backoff ni bloqueo por origen, y el espacio
  de contraseñas sigue siendo explorable a la velocidad a la que el atacante
  abra conexiones.
- **No enumeración de usuarios.** `AUTH` responde lo mismo ante usuario
  inexistente, contraseña incorrecta o usuario sin atributo de administrador;
  `ACCESS_LOG <username>` responde lista vacía tanto para usuarios sin accesos
  como inexistentes. Un atacante autenticado, en cambio, sí puede enumerar con
  `ADD_USER`/`DEL_USER` (respuestas `user exists`/`user not found`): se asume
  que quien está autenticado es de confianza.
- **Las contraseñas nunca salen.** `USERS` devuelve solo nombres; ningún
  comando permite leer contraseñas almacenadas.
- **Separación de privilegios.** Solo los usuarios con atributo de
  administrador acceden a este servicio, y el atributo solo puede otorgarse al
  lanzar el servidor: un atacante que comprometa una sesión de administración
  no puede crear nuevos administradores (`ADD_USER` crea solo usuarios comunes)
  ni, gracias a la protección del último admin (§8.7), dejar el servicio
  inadministrable de forma permanente — aunque sí puede eliminar usuarios
  comunes y administradores excedentes, o degradar el servicio vía `CONFIG`.
- **Privacidad del registro de accesos.** `ACCESS_LOG` expone la actividad de
  los usuarios del proxy (destinos y horarios) a cualquier administrador. La
  retención acotada (512 visitas por usuario, §10) limita la ventana expuesta
  y acota además la memoria que un cliente malicioso puede hacer crecer
  generando accesos en loop.
- **Denegación de servicio.** El largo máximo de línea (§5.2) y el cierre ante
  líneas excesivas acotan la memoria por sesión. El límite de sesiones
  simultáneas (§4) y el cierre por inactividad (§4.5) — con umbral corto para
  sesiones no autenticadas, que se abren sin acreditar identidad — impiden que
  un cliente que abre conexiones y no las usa acapare descriptores de archivo
  del proceso, que el servicio de monitoreo comparte con el proxy monitoreado:
  sin esos frenos, agotar el cupo de sesiones dejaría al proxy sin poder
  aceptar clientes SOCKS.

## 13. Referencias

- [RFC 1928] Leech, M. y otros, "SOCKS Protocol Version 5", marzo de 1996.
- [RFC 1929] Leech, M., "Username/Password Authentication for SOCKS V5",
  marzo de 1996.
- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, marzo de 1997.
- [RFC 5234] Crocker, D. y P. Overell, "Augmented BNF for Syntax
  Specifications: ABNF", enero de 2008.
- [RFC 7405] Kyzivat, P., "Case-Sensitive String Support in ABNF",
  diciembre de 2014.
- [RFC 8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words", BCP 14, mayo de 2017.

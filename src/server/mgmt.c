/**
 * mgmt.c -- servidor de monitoreo/administración del proxy SOCKSv5 (T32).
 *
 * Sigue el mismo patrón que socks5nio.c: este archivo es dueño del ciclo de
 * vida de la sesión (`struct mgmt_session', pool de reuso), de la tabla de
 * estados y de los handlers top-level que el selector invoca.
 *
 * La sesión tiene dos estados "vivos" (no autenticado / autenticado) que
 * comparten los mismos handlers de lectura y escritura: lo único que cambia
 * entre ellos es qué comandos se aceptan, y eso lo decide el dispatcher
 * consultando el estado actual. Separarlos en archivos como los state_*.c del
 * proxy sería ceremonia sin contenido.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>   // malloc
#include <string.h>   // memset, strchr, strcmp
#include <unistd.h>   // close

#include <sys/socket.h>   // recv, send, MSG_NOSIGNAL

#include "buffer.h"
#include "stm.h"
#include "include/mgmt.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

/** máximo de una línea de comando, contando el '\n' final (el contenido útil
 *  puede ocupar hasta MGMT_MAX_LINE - 1 bytes) */
#define MGMT_MAX_LINE          512
/** tamaño de los buffers crudos de I/O de la sesión */
#define MGMT_BUFFER_SIZE       1024
/**
 * espacio que exigimos libre en el write buffer ANTES de despachar una línea:
 * garantiza que la respuesta de una línea siempre entra entera (la más larga
 * de T32 es "-ERR already authenticated\n" = 27 bytes). Si no hay lugar, el
 * parseo se pausa (backpressure) en vez de truncar respuestas.
 */
#define MGMT_RESPONSE_RESERVE  64

/** máquina de estados de una sesión de administración */
enum mgmt_state {
    /**
     * el cliente todavía no se autenticó: solo se aceptan AUTH y QUIT, el
     * resto responde `-ERR not authenticated'.
     *
     * Intereses:
     *   - OP_READ  sobre client_fd (salvo pausa por backpressure)
     *   - OP_WRITE sobre client_fd mientras haya respuestas pendientes
     *
     * Transiciones:
     *   - MGMT_NOAUTH mientras no haya un AUTH exitoso
     *   - MGMT_AUTH   ante AUTH con credenciales de admin válidas
     *   - MGMT_DONE   QUIT (tras drenar el `+OK bye') o cierre del cliente
     *   - MGMT_ERROR  ante error de I/O
     */
    MGMT_NOAUTH,

    /**
     * el cliente ya se autenticó: se aceptan todos los comandos (AUTH pasa a
     * responder `-ERR already authenticated'). Mismos intereses y eventos que
     * MGMT_NOAUTH; solo cambia el criterio del dispatcher.
     *
     * Transiciones:
     *   - MGMT_AUTH  mientras la sesión siga viva
     *   - MGMT_DONE  QUIT o cierre del cliente
     *   - MGMT_ERROR ante error de I/O
     */
    MGMT_AUTH,

    // estados terminales
    MGMT_DONE,
    MGMT_ERROR,
};

/*
 * Sesión de una conexión de administración. Una única alocación por conexión,
 * con pool de reuso igual que `struct socks5'.
 */
struct mgmt_session {
    /** información de la conexión con el cliente */
    struct sockaddr_storage  client_addr;
    socklen_t                client_addr_len;
    int                      client_fd;

    /** máquina de estados de la sesión */
    struct state_machine     stm;

    /**
     * línea en construcción. Vive en la sesión (y no en el stack del handler)
     * porque una línea puede llegar partida en varios read(): la mitad ya
     * consumida tiene que sobrevivir entre eventos del selector.
     */
    char                     line[MGMT_MAX_LINE];
    size_t                   line_len;

    /**
     * true si hay que cerrar la conexión apenas se termine de drenar el write
     * buffer (QUIT, línea demasiado larga). Permite que el `+OK bye' llegue
     * entero aunque el send() sea parcial, y corta el consumo de más líneas.
     */
    bool                     closing;

    /** buffers crudos y sus vistas para I/O */
    uint8_t                  raw_buff_read[MGMT_BUFFER_SIZE];
    uint8_t                  raw_buff_write[MGMT_BUFFER_SIZE];
    buffer                   read_buffer, write_buffer;

    /** siguiente en el pool de reuso */
    struct mgmt_session     *next;
};

/** obtiene el struct (mgmt_session *) desde la llave de selección */
#define MGMT_ATTACHMENT(key) ((struct mgmt_session *)(key)->data)

/** tabla de usuarios (de args) contra la que valida AUTH; ver mgmt_init */
static const struct socks5args *mgmt_args = NULL;

void
mgmt_init(const struct socks5args *args) {
    mgmt_args = args;
}

///////////////////////////////////////////////////////////////////////////////
// Pool de sesiones (mismo esquema que socks5nio.c)

/** cantidad máxima de sesiones guardadas en el pool de reuso */
static const unsigned        max_pool  = 10;
static unsigned              pool_size = 0;
static struct mgmt_session  *pool      = NULL;

static const struct state_definition *
mgmt_describe_states(void);

/** crea una nueva sesión (reutiliza del pool si hay disponible) */
static struct mgmt_session *
mgmt_new(int client_fd) {
    struct mgmt_session *ret;

    if(pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret       = pool;
        pool      = pool->next;
        pool_size--;
        ret->next = NULL;
    }
    if(ret == NULL) {
        goto finally;
    }
    memset(ret, 0x00, sizeof(*ret));

    ret->client_fd       = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    ret->stm.initial     = MGMT_NOAUTH;
    ret->stm.max_state   = MGMT_ERROR;
    ret->stm.states      = mgmt_describe_states();
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer,  N(ret->raw_buff_read),  ret->raw_buff_read);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_write), ret->raw_buff_write);
finally:
    return ret;
}

/**
 * destruye una sesión (o la encola en el pool). A diferencia del proxy, una
 * sesión de monitoreo tiene un único fd asociado, así que cuando el selector
 * invoca handle_close no quedan otras referencias: no hace falta el contador
 * de referencias de `struct socks5'.
 */
static void
mgmt_session_destroy(struct mgmt_session *s) {
    if(s == NULL) {
        return;
    }
    if(pool_size < max_pool) {
        s->next = pool;
        pool    = s;
        pool_size++;
    } else {
        free(s);
    }
}

void
mgmt_pool_destroy(void) {
    struct mgmt_session *next, *s;
    for(s = pool; s != NULL; s = next) {
        next = s->next;
        free(s);
    }
    pool      = NULL;
    pool_size = 0;
}

///////////////////////////////////////////////////////////////////////////////
// Respuestas

/**
 * encola `msg' + '\n' en el write buffer. El interés OP_WRITE lo prende
 * mgmt_update_interests() al final del evento en curso.
 */
static void
mgmt_queue_line(struct mgmt_session *s, const char *msg) {
    const size_t len = strlen(msg);
    size_t space;
    uint8_t *ptr = buffer_write_ptr(&s->write_buffer, &space);

    if(space < len + 1) {
        // no debería ocurrir: mgmt_can_respond() reserva lugar antes de cada
        // despacho. Si igual pasa, cerrar es mejor que responder a medias.
        s->closing = true;
        return;
    }
    memcpy(ptr, msg, len);
    ptr[len] = '\n';
    buffer_write_adv(&s->write_buffer, (ssize_t)(len + 1));
}

/** true si el write buffer garantiza lugar para la respuesta de una línea */
static bool
mgmt_can_respond(struct mgmt_session *s) {
    size_t space;
    buffer_write_ptr(&s->write_buffer, &space);
    return space >= MGMT_RESPONSE_RESERVE;
}

/**
 * recalcula los intereses del fd según el estado de los buffers:
 *  - OP_READ  salvo que estemos cerrando o que no haya lugar garantizado para
 *    responder (backpressure: dejar de leer hasta drenar lo pendiente).
 *  - OP_WRITE mientras haya respuestas encoladas.
 */
static selector_status
mgmt_update_interests(struct selector_key *key) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);
    unsigned interest = OP_NOOP;

    if(!s->closing && mgmt_can_respond(s) && buffer_can_write(&s->read_buffer)) {
        interest |= OP_READ;
    }
    if(buffer_can_read(&s->write_buffer)) {
        interest |= OP_WRITE;
    }
    return selector_set_interest_key(key, (fd_interest)interest);
}

///////////////////////////////////////////////////////////////////////////////
// Comandos

/**
 * un comando de la tabla. El handler recibe el estado actual (para decidir
 * transiciones) y `args': el resto de la línea CRUDO desde el primer espacio,
 * o NULL si el comando vino solo. Retorna el próximo estado.
 */
struct mgmt_cmd {
    const char *name;
    /** si true, en MGMT_NOAUTH responde `-ERR not authenticated' */
    bool        requires_auth;
    unsigned  (*handler)(struct selector_key *key, unsigned state, char *args);
};

/** AUTH <user> <pass> -- login del administrador */
static unsigned
cmd_auth(struct selector_key *key, unsigned state, char *args) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);

    if(state == MGMT_AUTH) {
        // no se permite reautenticar
        mgmt_queue_line(s, "-ERR already authenticated");
        return state;
    }

    // user = hasta el primer espacio de args; pass = el resto tal cual (puede
    // contener espacios). Si falta alguno de los dos tokens, o el user es
    // vacío ("AUTH  x": doble espacio), los argumentos están mal formados.
    char *pass = (args == NULL) ? NULL : strchr(args, ' ');
    if(pass == NULL) {
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }
    *pass++ = '\0';
    if(args[0] == '\0') {
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }

    // scan lineal sobre la tabla de args (≤ MAX_USERS entradas): solo
    // usuarios con is_admin pueden entrar; un usuario común del proxy con
    // credenciales correctas recibe el mismo error que uno inexistente (no
    // filtramos información sobre qué usuarios existen).
    bool ok = false;
    if(mgmt_args != NULL) {
        for(int i = 0; i < mgmt_args->nusers && !ok; i++) {
            const struct users *u = &mgmt_args->users[i];
            ok = u->is_admin
              && strcmp(u->name, args) == 0    // case-sensitive
              && strcmp(u->pass, pass) == 0;
        }
    }
    if(ok) {
        mgmt_queue_line(s, "+OK authenticated");
        return MGMT_AUTH;
    }
    mgmt_queue_line(s, "-ERR invalid credentials");
    return state;
}

/** QUIT -- despedida y cierre ordenado */
static unsigned
cmd_quit(struct selector_key *key, unsigned state, char *args) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);

    if(args != NULL) {
        // QUIT no lleva argumentos
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }
    mgmt_queue_line(s, "+OK bye");
    // no cerramos acá: closing corta el consumo de nuevas líneas y
    // mgmt_cmd_write transiciona a MGMT_DONE recién cuando el bye salió entero
    s->closing = true;
    return state;
}

/**
 * stub para los comandos cuya lógica llega en tareas posteriores: el nombre
 * ya se reconoce (y exige autenticación) pero todavía no hacen nada. La
 * validación de argumentos de cada uno también llega con su implementación.
 */
static unsigned
cmd_not_implemented(struct selector_key *key, unsigned state, char *args) {
    (void)args;
    mgmt_queue_line(MGMT_ATTACHMENT(key), "-ERR not implemented");
    return state;
}

static const struct mgmt_cmd mgmt_commands[] = {
    { .name = "AUTH",        .requires_auth = false, .handler = cmd_auth            },
    { .name = "QUIT",        .requires_auth = false, .handler = cmd_quit            },
    // TODO(T42): STATS/USERS/CONNECTIONS -- métricas y listados de solo lectura
    { .name = "STATS",       .requires_auth = true,  .handler = cmd_not_implemented },
    { .name = "USERS",       .requires_auth = true,  .handler = cmd_not_implemented },
    { .name = "CONNECTIONS", .requires_auth = true,  .handler = cmd_not_implemented },
    // TODO(T53): CONFIG -- configuración de parámetros en runtime
    { .name = "CONFIG",      .requires_auth = true,  .handler = cmd_not_implemented },
    // TODO(T70): ADD_USER/DEL_USER -- alta y baja de usuarios del proxy
    { .name = "ADD_USER",    .requires_auth = true,  .handler = cmd_not_implemented },
    { .name = "DEL_USER",    .requires_auth = true,  .handler = cmd_not_implemented },
    // TODO(T71): ACCESS_LOG -- consulta del registro de accesos
    { .name = "ACCESS_LOG",  .requires_auth = true,  .handler = cmd_not_implemented },
};

/**
 * despacha una línea completa (ya sin '\n' ni '\r', NUL-terminada).
 * `line' se modifica in-place (se separa el comando de los argumentos).
 * Retorna el próximo estado de la sesión.
 */
static unsigned
mgmt_dispatch_line(struct selector_key *key, unsigned state, char *line) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);

    // el comando es el token hasta el primer espacio; el resto de la línea se
    // entrega CRUDO al handler (sin recortar espacios): por protocolo el
    // último argumento es "todo lo que sigue", y así un password con espacios
    // llega intacto.
    char *args = strchr(line, ' ');
    if(args != NULL) {
        *args++ = '\0';
    }

    // el strcmp exacto ya es case-sensitive y rechaza cualquier token fuera
    // de los 8 nombres (charset incluido), sin validación aparte.
    const struct mgmt_cmd *cmd = NULL;
    for(unsigned i = 0; i < N(mgmt_commands); i++) {
        if(strcmp(mgmt_commands[i].name, line) == 0) {
            cmd = &mgmt_commands[i];
            break;
        }
    }
    if(cmd == NULL) {
        mgmt_queue_line(s, "-ERR unknown command");   // sin cerrar la conexión
        return state;
    }
    if(cmd->requires_auth && state != MGMT_AUTH) {
        mgmt_queue_line(s, "-ERR not authenticated");
        return state;
    }
    return cmd->handler(key, state, args);
}

///////////////////////////////////////////////////////////////////////////////
// Parser de líneas
//
// No usa el motor parser.c de la cátedra: ese motor emite eventos por carácter
// (hasta 3 bytes por evento, sin acumulación), pensado para gramáticas por
// clases de caracteres como los mensajes binarios de SOCKS. Para framing por
// línea igual habría que acumular los bytes en un buffer propio, así que el
// motor no ahorra la parte delicada (acumular con límite y extraer el string)
// y solo agrega indirección.

/**
 * drena el read buffer hacia `s->line' y despacha cada línea completa.
 * Un read() puede traer media línea o varias juntas: este loop es el único
 * lugar que reconstruye el framing, y es invocado tanto por el evento de
 * lectura como por el de escritura (para retomar líneas pausadas por
 * backpressure). Retorna el próximo estado de la sesión.
 */
static unsigned
mgmt_consume_lines(struct selector_key *key) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);
    unsigned state = stm_state(&s->stm);

    while(!s->closing && buffer_can_read(&s->read_buffer)) {
        if(!mgmt_can_respond(s)) {
            // backpressure: sin lugar garantizado para la respuesta no se
            // despacha nada. Los bytes quedan en el read buffer y
            // mgmt_cmd_write retoma este loop cuando el cliente drene.
            break;
        }
        const uint8_t c = buffer_read(&s->read_buffer);
        if(c == '\n') {
            if(s->line_len > 0 && s->line[s->line_len - 1] == '\r') {
                s->line_len--;   // tolerar clientes que terminan en \r\n
            }
            s->line[s->line_len] = '\0';
            // el estado puede cambiar a mitad del lote (AUTH exitoso seguido
            // de otro comando en el mismo read): por eso se encadena acá y no
            // se consulta la stm de nuevo.
            state = mgmt_dispatch_line(key, state, s->line);
            s->line_len = 0;
        } else if(s->line_len == MGMT_MAX_LINE - 1) {
            // ya hay 511 bytes de contenido y no llegó el '\n': con este byte
            // la línea superaría los 512 (contando el fin de línea)
            mgmt_queue_line(s, "-ERR line too long");
            s->closing = true;   // el protocolo exige cerrar en este caso
        } else {
            s->line[s->line_len++] = (char)c;
        }
    }

    if(state != MGMT_ERROR && state != MGMT_DONE
       && SELECTOR_SUCCESS != mgmt_update_interests(key)) {
        state = MGMT_ERROR;
    }
    return state;
}

///////////////////////////////////////////////////////////////////////////////
// Handlers de los estados MGMT_NOAUTH / MGMT_AUTH (compartidos)

/** lee del socket al read buffer y procesa las líneas completas que haya */
static unsigned
mgmt_cmd_read(struct selector_key *key) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);
    size_t count;
    uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &count);

    const ssize_t n = recv(key->fd, ptr, count, 0);
    if(n == 0) {
        return MGMT_DONE;    // el cliente cerró ordenadamente
    }
    if(n < 0) {
        return MGMT_ERROR;
    }
    buffer_write_adv(&s->read_buffer, n);
    return mgmt_consume_lines(key);
}

/** vuelca el write buffer al socket, tolerando escrituras parciales */
static unsigned
mgmt_cmd_write(struct selector_key *key) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);
    size_t count;
    uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &count);

    const ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if(n == -1) {
        return MGMT_ERROR;
    }
    buffer_read_adv(&s->write_buffer, n);

    if(!buffer_can_read(&s->write_buffer) && s->closing) {
        // la despedida (o el error fatal) ya salió completa: recién ahora se
        // puede cerrar sin cortarla
        return MGMT_DONE;
    }
    // al liberar lugar pueden quedar líneas pausadas por backpressure en el
    // read buffer; hay que retomarlas acá porque no va a haber un nuevo
    // evento de lectura por datos que ya llegaron
    return mgmt_consume_lines(key);
}

/** definición de handlers para cada estado */
static const struct state_definition mgmt_statbl[] = {
    {
        .state          = MGMT_NOAUTH,
        .on_read_ready  = mgmt_cmd_read,
        .on_write_ready = mgmt_cmd_write,
    },
    {
        .state          = MGMT_AUTH,
        .on_read_ready  = mgmt_cmd_read,
        .on_write_ready = mgmt_cmd_write,
    },
    {
        .state          = MGMT_DONE,
    },
    {
        .state          = MGMT_ERROR,
    },
};

static const struct state_definition *
mgmt_describe_states(void) {
    return mgmt_statbl;
}

///////////////////////////////////////////////////////////////////////////////
// Handlers top level: emiten los eventos del selector a la máquina de estados
// (mismo esquema que socksv5_read/write/close).

static void
mgmt_done(struct selector_key *key);

static void
mgmt_read(struct selector_key *key) {
    struct state_machine *stm = &MGMT_ATTACHMENT(key)->stm;
    const unsigned st = stm_handler_read(stm, key);

    if(MGMT_ERROR == st || MGMT_DONE == st) {
        mgmt_done(key);
    }
}

static void
mgmt_write(struct selector_key *key) {
    struct state_machine *stm = &MGMT_ATTACHMENT(key)->stm;
    const unsigned st = stm_handler_write(stm, key);

    if(MGMT_ERROR == st || MGMT_DONE == st) {
        mgmt_done(key);
    }
}

// el fd lo cierra el handle_close (misma regla que socksv5_close): así el
// teardown del selector también cierra las sesiones de monitoreo aún vivas.
static void
mgmt_close(struct selector_key *key) {
    close(key->fd);
    mgmt_session_destroy(MGMT_ATTACHMENT(key));
}

/** cierre centralizado: desregistrar dispara mgmt_close, que cierra y libera */
static void
mgmt_done(struct selector_key *key) {
    const int fd = MGMT_ATTACHMENT(key)->client_fd;
    if(fd != -1) {
        if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fd)) {
            abort();
        }
    }
}

static const struct fd_handler mgmt_handler = {
    .handle_read  = mgmt_read,
    .handle_write = mgmt_write,
    .handle_close = mgmt_close,
    .handle_block = NULL,   // el monitoreo no descarga trabajo bloqueante
};

///////////////////////////////////////////////////////////////////////////////
// Aceptación

void
mgmt_passive_accept(struct selector_key *key) {
    struct sockaddr_storage  client_addr;
    socklen_t                client_addr_len = sizeof(client_addr);
    struct mgmt_session     *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr *)&client_addr,
                                                          &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = mgmt_new(client);
    if(state == NULL) {
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    // el saludo se pre-encola y viaja por el mismo camino de flush que
    // cualquier respuesta: por eso el interés inicial incluye OP_WRITE y no
    // hace falta un estado "greeting" aparte
    mgmt_queue_line(state, "+OK monitor ready");

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &mgmt_handler,
                                             OP_READ | OP_WRITE, state)) {
        goto fail;
    }
    return;
fail:
    if(client != -1) {
        close(client);
    }
    mgmt_session_destroy(state);
}

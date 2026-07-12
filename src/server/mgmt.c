/**
 * mgmt.c -- servidor de monitoreo/administración del proxy SOCKSv5.
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
#include <inttypes.h> // PRIu64
#include <limits.h>   // INT_MAX
#include <stdarg.h>   // va_list
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>    // vsnprintf
#include <stdlib.h>   // malloc
#include <string.h>   // memset, strchr, strcmp
#include <time.h>     // clock_gettime
#include <unistd.h>   // close

#include <sys/socket.h>   // recv, send, MSG_NOSIGNAL

#include "buffer.h"
#include "stm.h"
#include "config.h"
#include "metrics.h"
#include "netutils.h"    // transient_io_error
#include "include/args.h"   // MAX_USERS: acota USERS y la reserva de respuesta
#include "include/mgmt.h"
#include "utils/include/user_auth_utils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

/** máximo de una línea de comando, contando el '\n' final (el contenido útil
 *  puede ocupar hasta MGMT_MAX_LINE - 1 bytes) */
#define MGMT_MAX_LINE          512
/** tamaño del buffer crudo de lectura de la sesión */
#define MGMT_READ_BUFFER_SIZE  1024
/**
 * intentos de AUTH fallidos tolerados por sesión antes de cerrar la conexión:
 * sin freno, el canal (texto plano, sin cifrar) permite fuerza bruta de las
 * credenciales de admin al ritmo que el atacante quiera. Reconectar renueva
 * el cupo, pero obliga a pagar un handshake TCP por cada tanda.
 */
#define MGMT_MAX_AUTH_FAILURES 3
/**
 * tope de sesiones de monitoreo concurrentes. Sin tope no hay nada que frene a
 * un cliente que abre conexiones y no manda un solo byte: cada una se queda con
 * un fd para siempre. Y como el monitoreo vive en el MISMO selector que el
 * proxy, comparte con él el presupuesto de fds acotado por FD_SETSIZE, así que
 * agotarlo no solo voltea al monitoreo -- deja a socksv5_passive_accept sin
 * poder registrar clientes nuevos. El monitoreo es un canal de administración
 * (un puñado de sesiones alcanza) y el resto del presupuesto es del proxy, que
 * es quien da el servicio.
 */
#define MGMT_MAX_SESSIONS      16
/**
 * timeout de inactividad, en segundos, de una sesión que TODAVÍA NO autenticó.
 * Es el vector barato del ataque -- abrir sesiones no exige credencial -- así
 * que se corta agresivo: ningún cliente legítimo necesita medio minuto para
 * mandar su AUTH.
 */
#define MGMT_NOAUTH_TIMEOUT    30
/**
 * timeout de inactividad, en segundos, de una sesión ya autenticada. Es a
 * propósito que NO sea el `timeout' de config: ese es el contrato del proxy y
 * el admin puede bajarlo en caliente, con lo que un `CONFIG timeout 1' le
 * cerraría de rebote su propia sesión de monitoreo. Generoso, porque del otro
 * lado suele haber una persona tipeando en una terminal.
 */
#define MGMT_IDLE_TIMEOUT      600
/**
 * espacio que exigimos libre en el write buffer ANTES de despachar una línea:
 * garantiza que la respuesta entra siempre ENTERA, incluidas las multilínea.
 * La más grande posible es USERS con la tabla de usuarios llena: "+OK\n" +
 * MAX_USERS nombres de hasta 255 bytes con su '\n' (= MAX_USERNAME_LEN cada
 * uno) + ".\n" final. Si no hay lugar, el parseo se pausa (backpressure) en
 * vez de truncar respuestas, y mgmt_cmd_write lo retoma al drenar.
 *
 * Reservar el peor caso evita emitir listas "resumibles" cuando el peor caso
 * es chico y acotado: se paga con buffer y no con maquinaria. La excepción es
 * ACCESS_LOG, cuya respuesta NO está acotada: ese comando no depende de esta
 * reserva sino de la emisión pausable de mgmt_emit_log (ver log_lines).
 */
#define MGMT_RESPONSE_RESERVE  (4 + MAX_USERS * MAX_USERNAME_LEN + 2)
/**
 * tamaño del buffer crudo de escritura: el peor caso de una respuesta más
 * margen para las respuestas anteriores todavía no drenadas por el cliente.
 */
#define MGMT_WRITE_BUFFER_SIZE 4096

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

    /** AUTH fallidos en esta sesión (ver MGMT_MAX_AUTH_FAILURES) */
    unsigned                 auth_failures;

    /**
     * momento (reloj monótono, en segundos) del último evento de I/O de la
     * sesión. Lo consulta el barrido de inactividad; lo refrescan los handlers
     * top-level, igual que en el proxy.
     */
    time_t                   last_activity;

    /**
     * emisión resumible de ACCESS_LOG: la respuesta completa se materializa
     * en `log_lines' (una FOTO del historial tomada al despachar el comando,
     * en heap porque no está acotada) y se vuelca al write buffer al ritmo
     * que el cliente drena. `log_next' es el marcador de reanudación.
     * log_lines != NULL significa "multilínea en curso": bloquea el despacho
     * de nuevos comandos (sus respuestas se intercalarían en el medio) hasta
     * que salga el `.' final. log_next == log_count con la foto aún viva
     * quiere decir que falta solo ese `.'.
     */
    char                   (*log_lines)[ACCESS_LOG_LINE_LEN];
    size_t                   log_count;
    size_t                   log_next;

    /** buffers crudos y sus vistas para I/O */
    uint8_t                  raw_buff_read[MGMT_READ_BUFFER_SIZE];
    uint8_t                  raw_buff_write[MGMT_WRITE_BUFFER_SIZE];
    buffer                   read_buffer, write_buffer;

    /** siguiente en el pool de reuso */
    struct mgmt_session     *next;

    /** enlaces en la lista de sesiones vivas (ver live_head) */
    struct mgmt_session     *live_next, *live_prev;
};

/** obtiene el struct (mgmt_session *) desde la llave de selección */
#define MGMT_ATTACHMENT(key) ((struct mgmt_session *)(key)->data)

///////////////////////////////////////////////////////////////////////////////
// Pool de sesiones (mismo esquema que socks5nio.c)

/** cantidad máxima de sesiones guardadas en el pool de reuso */
static const unsigned        max_pool  = 10;
static unsigned              pool_size = 0;
static struct mgmt_session  *pool      = NULL;

/**
 * lista de sesiones vivas (alta en `mgmt_new', baja en `mgmt_session_destroy').
 * La recorre el barrido de inactividad, y su contador es el que acota
 * MGMT_MAX_SESSIONS. El proxy lleva la suya propia en socks5nio.c: son dos
 * poblaciones distintas, con topes y timeouts distintos.
 */
static struct mgmt_session  *live_head  = NULL;
static unsigned              live_count = 0;

static void
mgmt_live_link(struct mgmt_session *s) {
    s->live_prev = NULL;
    s->live_next = live_head;
    if(live_head != NULL) {
        live_head->live_prev = s;
    }
    live_head  = s;
    live_count++;
}

static void
mgmt_live_unlink(struct mgmt_session *s) {
    if(s->live_prev != NULL) {
        s->live_prev->live_next = s->live_next;
    } else {
        live_head = s->live_next;
    }
    if(s->live_next != NULL) {
        s->live_next->live_prev = s->live_prev;
    }
    s->live_next = s->live_prev = NULL;
    live_count--;
}

/**
 * marca ahora como última actividad de la sesión. Único punto de refresco: lo
 * llaman `mgmt_new' y los handlers top-level, así el resto del archivo ni se
 * entera de que el timeout de inactividad existe.
 */
static void
mgmt_touch(struct mgmt_session *s) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    s->last_activity = now.tv_sec;
}

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

    mgmt_touch(ret);
    mgmt_live_link(ret);
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
    // la sesión deja de estar viva: libera su cupo de MGMT_MAX_SESSIONS y sale
    // del recorrido del barrido (que si no la seguiría viendo desde el pool)
    mgmt_live_unlink(s);
    // si el cliente murió a mitad de un ACCESS_LOG la foto sigue viva; se
    // libera acá y no al reusar del pool (mgmt_new pisa el puntero con memset)
    free(s->log_lines);
    s->log_lines = NULL;
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
        // despacho. Si igual pasa, cerrar es mejor que responder a medias --
        // y dejar rastro, porque desde afuera sería indistinguible de un
        // cliente que simplemente se desconectó.
        fprintf(stderr, "mgmt: write buffer overflow (respuesta descartada), "
                        "se cierra la sesión\n");
        s->closing = true;
        return;
    }
    memcpy(ptr, msg, len);
    ptr[len] = '\n';
    buffer_write_adv(&s->write_buffer, (ssize_t)(len + 1));
}

/**
 * variante printf de mgmt_queue_line, para las líneas `campo: valor' de las
 * respuestas multilínea. El buffer local alcanza para el campo más largo con
 * un uint64_t completo (20 dígitos); vsnprintf trunca si algún día no.
 */
static void
mgmt_queue_linef(struct mgmt_session *s, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void
mgmt_queue_linef(struct mgmt_session *s, const char *fmt, ...) {
    char line[64];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    mgmt_queue_line(s, line);
}

/** true si el write buffer garantiza lugar para una respuesta completa
 *  (incluso la multilínea más grande; ver MGMT_RESPONSE_RESERVE) */
static bool
mgmt_can_respond(struct mgmt_session *s) {
    size_t space;
    buffer_write_ptr(&s->write_buffer, &space);
    return space >= MGMT_RESPONSE_RESERVE;
}

/** true si hay una respuesta multilínea a medio emitir (ver log_lines) */
static bool
mgmt_emitting(const struct mgmt_session *s) {
    return s->log_lines != NULL;
}

/**
 * vuelca al write buffer lo que quede de la foto de ACCESS_LOG, línea por
 * línea mientras haya lugar REAL (acá no juega MGMT_RESPONSE_RESERVE: la
 * foto puede superar cualquier reserva posible, por eso se emite pausable
 * en vez de exigir que la respuesta entre entera). Es el espejo del parseo
 * pausable de mgmt_consume_lines: si la próxima línea no entra, el marcador
 * log_next la sigue apuntando y mgmt_cmd_write reintenta tras cada drenaje
 * del cliente. Recién cuando salió la última línea se emite el `.' final y
 * se libera la foto (fin de la emisión).
 */
static void
mgmt_emit_log(struct mgmt_session *s) {
    if(!mgmt_emitting(s)) {
        return;
    }
    size_t space;
    while(s->log_next < s->log_count) {
        const char *line = s->log_lines[s->log_next];
        buffer_write_ptr(&s->write_buffer, &space);
        if(space < strlen(line) + 1) {   // +1 por el '\n'
            return;   // pausa: el marcador queda donde está
        }
        mgmt_queue_line(s, line);
        s->log_next++;
    }
    buffer_write_ptr(&s->write_buffer, &space);
    if(space < 2) {
        return;   // falta solo el ".\n"; se reintenta en el próximo drenaje
    }
    mgmt_queue_line(s, ".");
    free(s->log_lines);
    s->log_lines = NULL;
    s->log_count = 0;
    s->log_next  = 0;
}

/**
 * recalcula los intereses del fd según el estado de los buffers:
 *  - OP_READ  salvo que estemos cerrando, que no haya lugar garantizado para
 *    responder (backpressure: dejar de leer hasta drenar lo pendiente) o que
 *    haya una multilínea a medio emitir (los comandos que lleguen no podrían
 *    despacharse hasta el `.' final; mejor frenar al cliente en el socket).
 *  - OP_WRITE mientras haya respuestas encoladas.
 */
static selector_status
mgmt_update_interests(struct selector_key *key) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);
    unsigned interest = OP_NOOP;

    if(!s->closing && mgmt_can_respond(s) && !mgmt_emitting(s)
       && buffer_can_write(&s->read_buffer)) {
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

    // valida contra la misma tabla que consulta el auth SOCKS y que tocan
    // ADD_USER/DEL_USER: un usuario común del proxy (sin is_admin) con
    // credenciales correctas recibe el mismo error que uno inexistente (no
    // filtramos información sobre qué usuarios existen).
    if(check_if_valid_admin_credentials(args, pass) == 0x00) {
        mgmt_queue_line(s, "+OK authenticated");
        return MGMT_AUTH;
    }
    // freno a la fuerza bruta: al agotar los intentos se corta la sesión
    // (closing drena el error antes de cerrar, igual que el bye de QUIT)
    s->auth_failures++;
    if(s->auth_failures >= MGMT_MAX_AUTH_FAILURES) {
        mgmt_queue_line(s, "-ERR too many failed logins");
        s->closing = true;
        return state;
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
 * STATS -- fotografía de las métricas globales, en formato multilínea:
 * `+OK', una línea `campo: valor' por métrica, y el `.' final. Solo lee
 * (la foto es coherente porque todo corre en el hilo del selector).
 */
static unsigned
cmd_stats(struct selector_key *key, unsigned state, char *args) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);

    if(args != NULL) {
        // STATS no lleva argumentos; el error es SIEMPRE de una sola línea,
        // nunca se empieza la multilínea
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }

    metrics_snapshot snap;
    metrics_get_snapshot(&snap);

    mgmt_queue_line(s, "+OK");
    mgmt_queue_linef(s, "historical_connections: %" PRIu64, snap.historical_connections);
    mgmt_queue_linef(s, "concurrent_connections: %" PRIu64, snap.concurrent_connections);
    mgmt_queue_linef(s, "max_concurrent: %" PRIu64, snap.max_concurrent);
    mgmt_queue_linef(s, "active_users: %d", metrics_get_user_count());
    mgmt_queue_linef(s, "bytes_transferred: %" PRIu64, snap.bytes_transferred);
    mgmt_queue_linef(s, "uptime: %" PRIu64, snap.uptime_seconds);
    mgmt_queue_line(s, ".");
    return state;
}

/**
 * USERS -- lista multilínea de los usuarios activos ahora (conectados al
 * proxy). Solo el nombre: las contraseñas jamás salen por este canal.
 */
static unsigned
cmd_users(struct selector_key *key, unsigned state, char *args) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);

    if(args != NULL) {
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }

    // los activos son siempre un subconjunto de la tabla de usuarios de args,
    // así que MAX_USERS acota la copia; si metrics reportara más (no
    // debería), se trunca para no exceder el espacio que garantizó
    // MGMT_RESPONSE_RESERVE antes del despacho
    user_info users[MAX_USERS];
    int count = metrics_get_user_count();
    if(count > MAX_USERS) {
        count = MAX_USERS;
    }
    metrics_get_users(users, count);

    mgmt_queue_line(s, "+OK");   // lista vacía = `+OK' y `.' sin líneas
    for(int i = 0; i < count; i++) {
        mgmt_queue_line(s, users[i].username);
    }
    mgmt_queue_line(s, ".");
    return state;
}

/**
 * CONNECTIONS -- conteos agregados de conexiones del proxy, multilínea. No
 * hay detalle por conexión (origen/destino): metrics no registra esos datos
 * de las conexiones activas y mantenerlos tocaría el camino del relay; el
 * conteo actual y el pico alcanzan para monitorear la carga.
 */
static unsigned
cmd_connections(struct selector_key *key, unsigned state, char *args) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);

    if(args != NULL) {
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }

    mgmt_queue_line(s, "+OK");
    mgmt_queue_linef(s, "current_connections: %" PRIu64,
                     metrics_get_current_connections());
    mgmt_queue_linef(s, "max_concurrent: %" PRIu64,
                     metrics_get_max_concurrent_connections());
    mgmt_queue_line(s, ".");
    return state;
}

/**
 * parsea un entero decimal ESTRICTO en [1, max]: solo dígitos ASCII, al menos
 * uno, sin signo, espacios ni sufijos, y sin desbordar. Deja el valor en *out
 * y devuelve true; false ante cualquier desvío. No se usa atoi/strtoul porque
 * son demasiado permisivos para el protocolo: "30abc", " 30", "+30" o "-1"
 * tienen que rechazarse con `-ERR invalid value', no interpretarse.
 */
static bool
parse_positive_int(const char *s, unsigned long max, unsigned long *out) {
    if(s == NULL || *s == '\0') {
        return false;
    }
    unsigned long v = 0;
    for(; *s != '\0'; s++) {
        if(*s < '0' || *s > '9') {
            return false;
        }
        const unsigned d = (unsigned)(*s - '0');
        // ¿v*10 + d superaría max? chequeado ANTES de multiplicar para que
        // valores gigantes fallen por rango y no por overflow silencioso
        if(v > max / 10 || (v == max / 10 && d > max % 10)) {
            return false;
        }
        v = v * 10 + d;
    }
    if(v == 0) {   // "0" (o "000") no es un entero positivo
        return false;
    }
    *out = v;
    return true;
}

/**
 * CONFIG <param> <valor> -- ajusta un parámetro en runtime. Solo guarda el
 * valor en el módulo config (memoria, sin persistencia); el proxy lo lee al
 * crear conexiones nuevas, las vivas no cambian. Respuesta de una sola línea.
 */
static unsigned
cmd_config(struct selector_key *key, unsigned state, char *args) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);

    // param = hasta el primer espacio; value = el resto CRUDO (mismo criterio
    // de split que el dispatch). Si falta cualquiera de los dos tokens los
    // argumentos están mal formados; si sobran ("timeout 30 40") el espacio
    // extra queda dentro de value y lo rechaza la validación numérica.
    char *value = (args == NULL) ? NULL : strchr(args, ' ');
    if(value == NULL) {
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }
    *value++ = '\0';
    if(args[0] == '\0' || value[0] == '\0') {
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }

    // primero se resuelve el param y recién después se valida el valor: así
    // "CONFIG foo 30" da `unknown param' y no `invalid value'
    unsigned long v;
    if(strcmp(args, "timeout") == 0) {
        if(!parse_positive_int(value, CONFIG_TIMEOUT_MAX, &v)) {
            mgmt_queue_line(s, "-ERR invalid value");
            return state;
        }
        config_set_timeout((unsigned)v);
    } else if(strcmp(args, "buf_size") == 0) {
        // además del rango numérico, un piso: por debajo de
        // CONFIG_BUF_SIZE_MIN el proxy no puede serializar sus respuestas
        // (ver config.h) y toda conexión nueva nacería muerta.
        if(!parse_positive_int(value, CONFIG_BUF_SIZE_MAX, &v)
           || v < CONFIG_BUF_SIZE_MIN) {
            mgmt_queue_line(s, "-ERR invalid value");
            return state;
        }
        config_set_buf_size((size_t)v);
    } else {
        mgmt_queue_line(s, "-ERR unknown param");
        return state;
    }
    mgmt_queue_line(s, "+OK");
    return state;
}

/**
 * ACCESS_LOG [user] -- historial de accesos, multilínea y potencialmente
 * enorme (una línea por sitio visitado desde el arranque, sin filtro o de un
 * solo usuario). Es el único comando cuya respuesta NO se exige que entre
 * entera en el write buffer: acá se materializa completa en heap (una FOTO
 * del historial al momento del comando, con las líneas ya formateadas por
 * metrics_get_access_log) y mgmt_emit_log la drena en forma pausable.
 *
 * ¿Por qué foto y no iterar metrics con un marcador usuario/sitio? Porque
 * los arreglos internos del historial (all_time_users y cada sites_visited)
 * crecen por realloc con el tráfico del proxy: un puntero o índice guardado
 * entre eventos del selector puede quedar colgado si llegan accesos nuevos
 * a mitad de la emisión. La foto copia todo a memoria propia; lo que llegue
 * durante la emisión simplemente sale en la próxima consulta.
 */
static unsigned
cmd_access_log(struct selector_key *key, unsigned state, char *args) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);

    // 0 argumentos (todo el historial) o 1 (filtro por usuario); un espacio
    // dentro de args significa que vino más de un argumento
    if(args != NULL && (args[0] == '\0' || strchr(args, ' ') != NULL)) {
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }

    // primer pase: dimensionar la respuesta sumando site_count (filtrado si
    // corresponde). Las copias superficiales de user_info valen solo durante
    // ESTE evento del selector -- nada puede mutar metrics en el medio.
    const int nusers = metrics_get_all_time_user_count();
    size_t total = 0;
    if(nusers > 0) {
        user_info *users = malloc((size_t)nusers * sizeof(*users));
        if(users == NULL) {
            mgmt_queue_line(s, "-ERR internal error");
            return state;
        }
        metrics_get_all_time_users(users, nusers);
        for(int i = 0; i < nusers; i++) {
            if(args == NULL
               || strncmp(users[i].username, args, MAX_USERNAME_LEN) == 0) {
                total += (size_t)users[i].site_count;
            }
        }
        free(users);
    }

    if(total == 0) {
        // historial vacío o usuario sin accesos (o inexistente: el protocolo
        // no distingue): multilínea vacía, no un error
        mgmt_queue_line(s, "+OK");
        mgmt_queue_line(s, ".");
        return state;
    }

    // techo defensivo antes de la aritmética: por encima de INT_MAX/600
    // líneas se desbordarían tanto el (int) que espera el getter como la
    // multiplicación del malloc. Con el ring de 512 visitas por usuario,
    // llegar acá exigiría millones de usuarios distintos (el proceso muere
    // de memoria mucho antes); si igual pasara, error de una línea.
    if(total > (size_t)INT_MAX / ACCESS_LOG_LINE_LEN) {
        mgmt_queue_line(s, "-ERR internal error");
        return state;
    }

    // la foto se toma ANTES de encolar el `+OK': si el malloc falla, el
    // error todavía puede ser de una sola línea (la multilínea no empezó)
    char (*lines)[ACCESS_LOG_LINE_LEN] = malloc(total * sizeof(*lines));
    if(lines == NULL) {
        mgmt_queue_line(s, "-ERR internal error");
        return state;
    }
    const int written = metrics_get_access_log(args, lines, (int)total);

    s->log_lines = lines;
    s->log_count = (written > 0) ? (size_t)written : 0;
    s->log_next  = 0;
    mgmt_queue_line(s, "+OK");
    mgmt_emit_log(s);   // emite lo que entre ya; el resto, al drenar el cliente
    return state;
}

/** ADD_USER <user> <pass> -- alta de usuario del proxy en runtime */
static unsigned
cmd_add_user(struct selector_key *key, unsigned state, char *args) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);

    // mismo split que AUTH: user hasta el primer espacio, pass el resto
    // crudo (puede contener espacios).
    char *pass = (args == NULL) ? NULL : strchr(args, ' ');
    if(pass == NULL || args[0] == '\0') {
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }
    *pass++ = '\0';

    switch(add_user_credentials(args, pass)) {
    case USER_ADD_OK:
        mgmt_queue_line(s, "+OK");
        break;
    case USER_ADD_EXISTS:
        mgmt_queue_line(s, "-ERR user exists");
        break;
    case USER_ADD_FULL:
        mgmt_queue_line(s, "-ERR user table full");
        break;
    case USER_ADD_INVALID:
    default:
        mgmt_queue_line(s, "-ERR invalid arguments");
        break;
    }
    return state;
}

/** DEL_USER <user> -- baja de usuario del proxy en runtime */
static unsigned
cmd_del_user(struct selector_key *key, unsigned state, char *args) {
    struct mgmt_session *s = MGMT_ATTACHMENT(key);

    if(args == NULL || args[0] == '\0') {
        mgmt_queue_line(s, "-ERR invalid arguments");
        return state;
    }

    switch(delete_user_credentials(args)) {
    case USER_DEL_OK:
        mgmt_queue_line(s, "+OK");
        break;
    case USER_DEL_NOT_FOUND:
        mgmt_queue_line(s, "-ERR user not found");
        break;
    case USER_DEL_LAST_ADMIN:
        mgmt_queue_line(s, "-ERR cannot delete last admin");
        break;
    }
    return state;
}

static const struct mgmt_cmd mgmt_commands[] = {
    { .name = "AUTH",        .requires_auth = false, .handler = cmd_auth            },
    { .name = "QUIT",        .requires_auth = false, .handler = cmd_quit            },
    { .name = "STATS",       .requires_auth = true,  .handler = cmd_stats           },
    { .name = "USERS",       .requires_auth = true,  .handler = cmd_users           },
    { .name = "CONNECTIONS", .requires_auth = true,  .handler = cmd_connections     },
    { .name = "CONFIG",      .requires_auth = true,  .handler = cmd_config          },
    { .name = "ADD_USER",    .requires_auth = true,  .handler = cmd_add_user        },
    { .name = "DEL_USER",    .requires_auth = true,  .handler = cmd_del_user        },
    { .name = "ACCESS_LOG",  .requires_auth = true,  .handler = cmd_access_log      },
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

    // mientras haya una multilínea a medio emitir tampoco se despacha: la
    // respuesta del próximo comando se intercalaría dentro de la lista. Las
    // líneas pipelineadas esperan en el read buffer hasta el `.' final.
    while(!s->closing && !mgmt_emitting(s) && buffer_can_read(&s->read_buffer)) {
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
        return transient_io_error() ? stm_state(&s->stm) : MGMT_ERROR;
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
        return transient_io_error() ? stm_state(&s->stm) : MGMT_ERROR;
    }
    buffer_read_adv(&s->write_buffer, n);

    // primero retomar una multilínea pausada: la emisión tiene prioridad
    // sobre despachar comandos nuevos (que siguen esperando en el read buffer)
    mgmt_emit_log(s);

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
    mgmt_touch(MGMT_ATTACHMENT(key));
    const unsigned st = stm_handler_read(stm, key);

    if(MGMT_ERROR == st || MGMT_DONE == st) {
        mgmt_done(key);
    }
}

static void
mgmt_write(struct selector_key *key) {
    struct state_machine *stm = &MGMT_ATTACHMENT(key)->stm;
    mgmt_touch(MGMT_ATTACHMENT(key));
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
    // tope de sesiones concurrentes. Se acepta igual y se rechaza con una línea
    // de protocolo, en vez de dejar la conexión esperando en la cola de accept:
    // el pasivo es level-triggered, así que una conexión pendiente lo mantiene
    // readable y el selector volvería a llamarnos en cada vuelta del loop.
    // Aceptar-y-cerrar la drena y le da al cliente un motivo en vez de un
    // cierre mudo. El send es best-effort (socket recién nacido, buffer vacío:
    // la línea entra entera); si fallara, el cliente igual ve el cierre.
    if(live_count >= MGMT_MAX_SESSIONS) {
        static const char full[] = "-ERR too many sessions\n";
        send(client, full, sizeof(full) - 1, MSG_NOSIGNAL);
        close(client);
        return;
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

///////////////////////////////////////////////////////////////////////////////
// Barrido de inactividad

void
mgmt_sweep_timeouts(fd_selector s) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    const time_t now = ts.tv_sec;

    struct mgmt_session *next;
    for(struct mgmt_session *c = live_head; c != NULL; c = next) {
        // el cierre destruye el nodo actual: guardar el siguiente antes
        next = c->live_next;
        const unsigned state = stm_state(&c->stm);
        if(state == MGMT_DONE || state == MGMT_ERROR) {
            continue;   // ya están muriendo solas
        }
        // el umbral depende de si la sesión llegó a autenticarse: la que no lo
        // hizo no probó ser nadie y es la que un atacante puede abrir a
        // voluntad (ver MGMT_NOAUTH_TIMEOUT)
        const time_t timeout = (state == MGMT_AUTH) ? MGMT_IDLE_TIMEOUT
                                                    : MGMT_NOAUTH_TIMEOUT;
        if(now - c->last_activity >= timeout) {
            struct selector_key key = {
                .s    = s,
                .fd   = c->client_fd,
                .data = c,
            };
            mgmt_done(&key);   // desregistra -> mgmt_close cierra y libera
        }
    }
}

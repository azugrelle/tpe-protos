/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 *
 * Este archivo es dueño del ciclo de vida de la conexión (`struct socks5',
 * pool de reuso), de la tabla de estados y de los handlers top-level que el
 * selector invoca. La lógica de cada estado vive en `states/state_*.c'.
 */
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <time.h>    // clock_gettime
#include <unistd.h>  // close

#include <sys/socket.h>

#include "config.h"
#include "metrics.h"
#include "stm.h"
#include "include/socks5nio.h"
#include "include/socks5_state.h"

#include "states/include/state_hello.h"
#include "states/include/state_auth.h"
#include "states/include/state_request.h"
#include "states/include/state_connect.h"
#include "states/include/state_copy.h"

/** cantidad máxima de estructuras `socks5' guardadas en el pool de reuso */
static const unsigned  max_pool  = 50;
static unsigned        pool_size = 0;
static struct socks5 * pool      = 0;

/**
 * lista de conexiones vivas (alta en `socks5_new', baja al morir la última
 * referencia). El drenado del apagado la consulta para saber cuándo terminó.
 */
static struct socks5 * live_head  = NULL;
static unsigned        live_count = 0;

static void
socks5_live_link(struct socks5 *s) {
    s->live_prev = NULL;
    s->live_next = live_head;
    if(live_head != NULL) {
        live_head->live_prev = s;
    }
    live_head  = s;
    live_count++;
}

static void
socks5_live_unlink(struct socks5 *s) {
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

unsigned
socksv5_live_count(void) {
    return live_count;
}

/**
 * modo drenado del apagado ordenado: una vez activo, una resolución de DNS que
 * termine tarde cierra su conexión en vez de avanzar a CONNECTING (si no, ese
 * fd nuevo escaparía al barrido de cierre, que corre una sola vez, y podría
 * impedir para siempre que el drenado termine).
 */
static bool draining = false;

void
socksv5_start_draining(void) {
    draining = true;
}

bool
socksv5_is_draining(void) {
    return draining;
}

static const struct state_definition *
socks5_describe_states(void);

/**
 * marca ahora como última actividad de la conexión. Único punto de refresco:
 * lo llaman `socks5_new' y los handlers top-level, así los `state_*.c' ni se
 * enteran de que el timeout de inactividad existe.
 */
static void
socks5_touch(struct socks5 *s) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    s->last_activity = now.tv_sec;
}

/** crea un nuevo `struct socks5' (reutiliza del pool si hay disponible) */
static struct socks5 *
socks5_new(int client_fd) {
    struct socks5 *ret;

    // tope de conexiones concurrentes (MAX_CONNECTIONS = 511: dos fds por
    // conexión más los pasivos entran justo en el FD_SETSIZE de select).
    // Chequear acá y contabilizar recién al final del camino feliz es seguro
    // porque todo corre en el hilo del selector: no hay carrera entre ambos.
    if(metrics_get_current_connections() >= MAX_CONNECTIONS) {
        return NULL;
    }

    // los buffers de una estructura reciclada sobreviven al memset: se
    // guardan acá y, si el tamaño configurado no cambió, se reusan.
    uint8_t *buff_a   = NULL, *buff_b = NULL;
    size_t   buf_size = 0;

    if(pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret       = pool;
        pool      = pool->next;
        ret->next = 0;
        buff_a    = ret->raw_buff_a;
        buff_b    = ret->raw_buff_b;
        buf_size  = ret->buf_size;
    }
    if(ret == NULL) {
        goto finally;
    }
    memset(ret, 0x00, sizeof(*ret));

    // el tamaño lo dicta la config en ESTE momento: un CONFIG buf_size nuevo
    // aplica a las conexiones que nacen de acá en más; las vivas conservan
    // el suyo hasta morir.
    const size_t wanted = config_get_buf_size();
    if(buf_size != wanted) {
        free(buff_a);
        free(buff_b);
        buff_a = malloc(wanted);
        buff_b = malloc(wanted);
        if(buff_a == NULL || buff_b == NULL) {
            free(buff_a);
            free(buff_b);
            free(ret);
            ret = NULL;
            goto finally;
        }
    }
    ret->raw_buff_a = buff_a;
    ret->raw_buff_b = buff_b;
    ret->buf_size   = wanted;

    ret->origin_fd       = -1;
    ret->client_fd       = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    // hasta que AUTH_WRITE confirme credenciales, la conexión es anónima
    // (también el valor final si el cliente eligió no-auth).
    strncpy(ret->username, "anonymous", sizeof(ret->username) - 1);
    ret->username[sizeof(ret->username) - 1] = '\0';

    ret->stm.initial     = HELLO_READ;
    ret->stm.max_state   = ERROR;
    ret->stm.states      = socks5_describe_states();
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer,  ret->buf_size, ret->raw_buff_a);
    buffer_init(&ret->write_buffer, ret->buf_size, ret->raw_buff_b);

    ret->references = 1;

    socks5_touch(ret);
    socks5_live_link(ret);
    metrics_connection_start();   // la baja está junto a live_unlink, 1:1
finally:
    return ret;
}

/**
 * libera los recursos por-conexión (no la estructura en sí): hoy, la resolución
 * del origen. Corre al cerrar la última referencia, tanto antes de encolar en el
 * pool como al destruir de verdad, para que el `addrinfo' no se filtre si la
 * estructura se reutiliza (el pool no pasa por `socks5_destroy_'). Idempotente.
 *
 * Regla: todo recurso por-conexión se libera ACÁ. Los `on_departure' de la STM
 * no corren en el apagado (ni en el barrido de handshakes ni en el teardown de
 * selector_destroy), así que liberar algo solo en un on_departure lo fugaría.
 */
static void
socks5_cleanup(struct socks5 *s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = NULL;
    }
    s->origin_resolution_current = NULL;
}

/** realmente destruye */
static void
socks5_destroy_(struct socks5* s) {
    socks5_cleanup(s);
    free(s->raw_buff_a);
    free(s->raw_buff_b);
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        // última referencia: la conexión deja de estar viva (el camino de
        // references -= 1 no toca la lista: todavía queda quien la use).
        socks5_live_unlink(s);
        // espejo del alta al final de socks5_new. remove_user es no-op si la
        // conexión nunca pasó un AUTH exitoso ("anonymous" no está en la
        // lista de activos de metrics).
        metrics_connection_end();
        metrics_remove_user(s->username);
        // liberar recursos por-conexión antes de poolear, porque el pool
        // reutiliza la estructura sin pasar por socks5_destroy_.
        socks5_cleanup(s);
        if(pool_size < max_pool) {
            s->next = pool;
            pool    = s;
            pool_size++;
        } else {
            socks5_destroy_(s);
        }
    } else {
        s->references -= 1;
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        // las estructuras del pool guardan sus buffers vivos para reusarlos
        free(s->raw_buff_a);
        free(s->raw_buff_b);
        free(s);
    }
}

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

const fd_handler *
socks5_handler_ref(void) {
    return &socks5_handler;
}

/** Intenta aceptar la nueva conexión entrante*/
void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct socks5                *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = socks5_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state            = HELLO_READ,
        .on_arrival       = hello_read_init,
        .on_departure     = hello_read_close,
        .on_read_ready    = hello_read,
    },
    {
        .state            = HELLO_WRITE,
        .on_write_ready   = hello_write,
    },
    {
        // sin on_arrival: la iniciación es auth_start (llamada desde
        // hello_write), que procesa inline bytes pipelineados y por eso
        // puede transicionar (on_arrival no puede) — puede incluso saltear
        // este estado si el mensaje ya llegó completo.
        .state            = AUTH_READ,
        .on_departure     = auth_read_close,
        .on_read_ready    = auth_read,
    },
    {
        .state            = AUTH_WRITE,
        .on_write_ready   = auth_write,
    },
    {
        // sin on_arrival: la iniciación es request_start (llamada desde
        // hello_write / auth_write), por el mismo motivo que AUTH_READ.
        .state            = REQUEST_READ,
        .on_departure     = request_read_close,
        .on_read_ready    = request_read,
    },
    {
        .state            = REQUEST_WRITE,
        .on_write_ready   = request_write,
    },
    {
        // sin on_arrival por el mismo motivo que CONNECTING: la iniciación
        // (resolve_start) puede fallar y on_arrival no puede transicionar.
        .state            = RESOLVING,
        .on_block_ready   = resolve_done,
    },
    {
        .state            = CONNECTING,
        .on_write_ready   = connecting,
    },
    {
        // sin on_arrival: la activación del relay es copy_start (puede fallar
        // y on_arrival no puede transicionar), llamada desde request_write.
        .state            = COPY,
        .on_read_ready    = copy_r,
        .on_write_ready   = copy_w,
    },
    {
        .state            = DONE,
    },
    {
        .state            = ERROR,
    },
};

static const struct state_definition *
socks5_describe_states(void) {
    return client_statbl;
}

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
socksv5_done(struct selector_key* key);

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    socks5_touch(ATTACHMENT(key));
    const enum socks_v5state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    socks5_touch(ATTACHMENT(key));
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    // la notificación de DNS también es progreso: sin esto, una resolución
    // lenta dejaría a la conexión "inactiva" justo al salir de RESOLVING.
    socks5_touch(ATTACHMENT(key));
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

/**
 * el fd registrado lo cierra su handle_close, no quien desregistra: así
 * selector_destroy también cierra los fds de las conexiones que sigan vivas
 * en el teardown (antes solo liberaba la estructura y los filtraba).
 */
static void
socksv5_close(struct selector_key *key) {
    close(key->fd);
    socks5_destroy(ATTACHMENT(key));
}

static void
socksv5_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            // el unregister dispara socksv5_close, que cierra el fd
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
        }
    }
}

void
socksv5_shutdown_handshakes(fd_selector s) {
    struct socks5 *next;
    for(struct socks5 *c = live_head; c != NULL; c = next) {
        // el cierre destruye el nodo actual: guardar el siguiente antes
        next = c->live_next;
        switch(stm_state(&c->stm)) {
            // lista positiva de estados sin transferencia útil que drenar.
            // COPY queda afuera adrede (es lo que el drenado protege) y
            // RESOLVING también: mientras el hilo de DNS corre nada puede
            // desregistrar su client_fd; esa conexión se cierra sola vía
            // resolve_done al notificar (ver socksv5_is_draining).
            case HELLO_READ:   case HELLO_WRITE:
            case AUTH_READ:    case AUTH_WRITE:
            case REQUEST_READ: case REQUEST_WRITE:
            case CONNECTING: {
                struct selector_key key = {
                    .s    = s,
                    .fd   = c->client_fd,
                    .data = c,
                };
                socksv5_done(&key);
                break;
            }
            default:
                break;
        }
    }
}

void
socksv5_sweep_timeouts(fd_selector s) {
    // el timeout se lee acá, en cada pasada, y no se guarda por conexión:
    // así un CONFIG timeout nuevo afecta a TODAS las conexiones vivas en la
    // próxima evaluación, sin tocar memoria viva.
    const time_t timeout = (time_t) config_get_timeout();
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    const time_t now = ts.tv_sec;

    struct socks5 *next;
    for(struct socks5 *c = live_head; c != NULL; c = next) {
        // el cierre destruye el nodo actual: guardar el siguiente antes
        next = c->live_next;
        switch(stm_state(&c->stm)) {
            // RESOLVING no se toca: mientras el hilo de DNS corre nada puede
            // desregistrar su client_fd (notificaría sobre memoria liberada);
            // al notificar vuelve a ser alcanzable por la pasada siguiente.
            // DONE/ERROR ya están muriendo solas. A diferencia del barrido
            // del apagado, COPY sí entra: una transferencia ociosa es
            // exactamente el caso que el timeout existe para cerrar.
            case RESOLVING:
            case DONE:
            case ERROR:
                break;
            default:
                if(now - c->last_activity >= timeout) {
                    struct selector_key key = {
                        .s    = s,
                        .fd   = c->client_fd,
                        .data = c,
                    };
                    socksv5_done(&key);
                }
                break;
        }
    }
}

/**
 * state_connect.c -- estados RESOLVING y CONNECTING del proxy SOCKSv5
 * (RFC 1928 §6).
 *
 * Dueño de la resolución del destino y de la conexión no bloqueante al
 * origen. `request_process' hace `return connect_start()' en el camino
 * válido; cuando el connect termina se manda el REPLY real y se pasa a
 * REQUEST_WRITE.
 *
 * La resolución depende del ATYP: los literales IPv4/IPv6 se resuelven
 * inline (`AI_NUMERICHOST', sin lookup de red), pero un FQDN puede demorar
 * segundos y bloquearía el loop entero, así que corre en un hilo efímero
 * (estado RESOLVING) que al terminar despierta al selector con la
 * notificación de bloqueo y la conexión retoma en `resolve_done', ya en el
 * hilo principal.
 *
 * Con la resolución lista, `connect_try' arranca un `connect' no bloqueante
 * sobre el origin_fd, que se registra en el selector con interés OP_WRITE; el
 * cliente queda en OP_NOOP hasta que haya REPLY. `connecting' se dispara
 * cuando el origen queda escribible: consulta SO_ERROR y, según el resultado,
 * responde éxito, prueba el siguiente candidato o responde el error.
 */
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>        // snprintf
#include <stdlib.h>       // malloc, free
#include <string.h>       // memset, memcpy
#include <unistd.h>       // close
#include <netdb.h>        // getaddrinfo, AI_NUMERICHOST
#include <sys/socket.h>   // socket, connect, getsockopt, getsockname, SO_ERROR
#include <netinet/in.h>   // IPPROTO_TCP, sockaddr_in
#include <arpa/inet.h>    // ntohs

#include "include/state_connect.h"
#include "include/state_request.h"           // request_reply
#include "parsers/include/request_parser.h"  // SOCKS5_ATYP_IPV4, SOCKS5_REP_*
#include "include/socks5nio.h"               // socks5_handler_ref
#include "metrics.h"                         // metrics_add_user_site (ACCESS_LOG)

/** vuelca dest_port a texto para metrics_add_user_site (que espera char*) */
static void
dest_port_str(uint16_t port, char out[MAX_PORT_LEN]) {
    snprintf(out, MAX_PORT_LEN, "%u", (unsigned)port);
}

/** BND.ADDR de los replies mientras no hay BND real (0.0.0.0) */
static const uint8_t bnd_addr_none[4] = {0, 0, 0, 0};

/**
 * traduce el errno de un fallo de connect() al código REP del reply
 * (RFC 1928 §6). No se usa 0x06 (TTL expired) para un timeout de connect.
 */
static uint8_t
errno_to_rep(int e) {
    switch(e) {
        case ECONNREFUSED: return SOCKS5_REP_CONN_REFUSED;         // 0x05
        case ENETUNREACH:  return SOCKS5_REP_NETWORK_UNREACHABLE;  // 0x03
        case EHOSTUNREACH: return SOCKS5_REP_HOST_UNREACHABLE;     // 0x04
        case ETIMEDOUT:    return SOCKS5_REP_HOST_UNREACHABLE;     // 0x04
        default:           return SOCKS5_REP_GENERAL_FAILURE;      // 0x01
    }
}

/**
 * traduce el código de retorno de getaddrinfo (EAI_*, no errno) al REP del
 * reply. Los fallos de recurso/internos son general failure; el resto (el host
 * no resuelve) se reporta como host unreachable.
 */
static uint8_t
gai_error_to_rep(int gai) {
    switch(gai) {
        case EAI_MEMORY:
        case EAI_SYSTEM: return SOCKS5_REP_GENERAL_FAILURE;   // 0x01
        default:         return SOCKS5_REP_HOST_UNREACHABLE;  // 0x04
    }
}

/**
 * resuelve un destino literal (dest_host:dest_port, ATYP IPv4/IPv6) a una
 * lista de `addrinfo' lista para `connect'. Es síncrono porque no bloquea:
 * `AI_NUMERICHOST' garantiza que no hay lookup de red, solo parseo del
 * literal. Un FQDN no pasa por acá (va al hilo de resolución) y con este
 * hint fallaría con EAI_NONAME.
 *
 * Deja la lista en `s->origin_resolution' y el cursor en
 * `s->origin_resolution_current'.
 *
 * Devuelve el código de retorno de `getaddrinfo' (0 éxito, EAI_* en error).
 */
static int
connect_resolve(struct socks5 *s) {
    char port_str[6];   // "65535" + '\0'
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)s->dest_port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags    = AI_NUMERICHOST;
    hints.ai_family   = (s->dest_atyp == SOCKS5_ATYP_IPV6) ? AF_INET6
                                                           : AF_INET;

    s->origin_resolution = NULL;
    const int gai = getaddrinfo(s->dest_host, port_str, &hints,
                                &s->origin_resolution);
    if(gai != 0) {
        s->origin_resolution         = NULL;
        s->origin_resolution_current = NULL;
        return gai;
    }
    s->origin_resolution_current = s->origin_resolution;
    return 0;
}

//////////////////////////////////////////////////////////////////////
// Helpers de cleanup con una única invariante, para no repartir el manejo
// del origin_fd / addrinfo / references entre los muchos caminos de error.

/**
 * cierra el origin_fd: si `registered' lo desregistra del selector, y es el
 * handle_close disparado por el unregister quien cierra el fd (y decrementa
 * `references'); si no está registrado no hay handle_close que lo cubra, así
 * que se cierra acá. No-op si ya vale -1. Deja siempre origin_fd en -1.
 */
static void
connect_close_origin(struct socks5 *s, fd_selector sel, bool registered) {
    if(s->origin_fd == -1) {
        return;
    }
    if(registered) {
        selector_unregister_fd(sel, s->origin_fd);
    } else {
        close(s->origin_fd);
    }
    s->origin_fd = -1;
}

/** libera la resolución del origen a lo sumo una vez y anula lista + cursor */
static void
connect_free_resolution(struct socks5 *s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = NULL;
    }
    s->origin_resolution_current = NULL;
}

/** limpia la dirección remota activa (ya no hay un origen en juego) */
static void
connect_clear_active_addr(struct socks5 *s) {
    s->origin_addr_len = 0;
    memset(&s->origin_addr, 0, sizeof(s->origin_addr));
}

/**
 * fracaso terminal del connect: limpia el estado del origen, serializa el REPLY
 * de error y habilita al cliente para enviarlo. Devuelve el próximo estado
 * (REQUEST_WRITE, o ERROR si no se pudo dejar el REPLY listo sobre el cliente).
 */
static unsigned
connect_fail(struct socks5 *s, fd_selector sel, uint8_t rep) {
    connect_clear_active_addr(s);
    connect_free_resolution(s);

    char port_str[MAX_PORT_LEN];
    dest_port_str(s->dest_port, port_str);
    metrics_add_user_site(s->username, s->dest_host, port_str, false);

    if(request_reply(s, rep, SOCKS5_ATYP_IPV4, bnd_addr_none, 0) < 0) {
        return ERROR;
    }
    if(selector_set_interest(sel, s->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

//////////////////////////////////////////////////////////////////////

/**
 * recorre los candidatos de la resolución intentando un `connect' no bloqueante.
 * En el primer candidato "activo" (connect da 0 o EINPROGRESS) copia la dirección
 * remota, registra el origin_fd, pone el cliente en OP_NOOP y pasa a CONNECTING.
 * Si un candidato falla, cierra su fd y prueba el siguiente. Agotados todos,
 * responde el error.
 *
 * `errno' es volátil (close/selector lo pisan): se captura inmediatamente tras
 * cada syscall fallida. Un error de connect() (verdicto de red) tiene precedencia
 * sobre uno de socket()/nio (recurso local) al elegir el REP.
 */
static unsigned
connect_try(struct selector_key *key) {
    struct socks5     *s = ATTACHMENT(key);
    struct connecting *d = &s->orig.conn;

    while(s->origin_resolution_current != NULL) {
        struct addrinfo *ai = s->origin_resolution_current;

        s->origin_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if(s->origin_fd == -1) {
            const int e = errno;
            if(!d->had_connect_error) {
                d->last_error = e;
            }
            connect_close_origin(s, key->s, false);
            s->origin_resolution_current = ai->ai_next;
            continue;
        }

        if(selector_fd_set_nio(s->origin_fd) == -1) {
            const int e = errno;
            if(!d->had_connect_error) {
                d->last_error = e;
            }
            connect_close_origin(s, key->s, false);
            s->origin_resolution_current = ai->ai_next;
            continue;
        }

        const int r             = connect(s->origin_fd, ai->ai_addr, ai->ai_addrlen);
        const int connect_errno = errno;
        if(r == 0 || connect_errno == EINPROGRESS) {
            // candidato activo: copiamos la dirección remota antes de registrar.
            if(ai->ai_addrlen <= sizeof(s->origin_addr)) {
                memset(&s->origin_addr, 0, sizeof(s->origin_addr));
                memcpy(&s->origin_addr, ai->ai_addr, ai->ai_addrlen);
                s->origin_addr_len = ai->ai_addrlen;
            }
            // registrar el origin_fd antes de tocar el interés del cliente: si
            // algo falla después, socksv5_done encuentra ambos fds registrados.
            if(selector_register(key->s, s->origin_fd, socks5_handler_ref(),
                                 OP_WRITE, s) != SELECTOR_SUCCESS) {
                connect_close_origin(s, key->s, false);
                return connect_fail(s, key->s, SOCKS5_REP_GENERAL_FAILURE);
            }
            s->references++;
            // el cliente espera el REPLY: no leemos protocolo suyo durante el
            // connect (si mandara bytes con OP_READ la STM haría abort()).
            if(selector_set_interest(key->s, s->client_fd, OP_NOOP)
               != SELECTOR_SUCCESS) {
                return ERROR;
            }
            return CONNECTING;
        }

        // connect falló de inmediato: es un verdicto de red y tiene precedencia.
        d->last_error         = connect_errno;
        d->had_connect_error  = true;
        connect_close_origin(s, key->s, false);
        s->origin_resolution_current = ai->ai_next;
    }

    // candidatos agotados sin conectar.
    return connect_fail(s, key->s, errno_to_rep(d->last_error));
}

/** inicia la resolución + conexión no bloqueante al origen */
unsigned
connect_start(struct selector_key *key) {
    struct socks5     *s = ATTACHMENT(key);
    struct connecting *d = &s->orig.conn;

    d->last_error        = 0;
    d->had_connect_error = false;
    if(s->dest_atyp == SOCKS5_ATYP_DOMAIN) {
        // un FQDN puede demorar: la resolución va a un hilo aparte.
        return resolve_start(key);
    }
    const int gai = connect_resolve(s);
    if(gai != 0) {
        return connect_fail(s, key->s, gai_error_to_rep(gai));
    }
    return connect_try(key);
}

//////////////////////////////////////////////////////////////////////
// Resolución de FQDN en un hilo efímero (estado RESOLVING).

/**
 * cantidad de hilos de resolución vivos. El apagado del server la necesita
 * en cero antes de destruir el selector y las conexiones: un hilo tardío
 * escribiría sobre memoria liberada.
 */
static unsigned        resolve_inflight = 0;
static pthread_mutex_t resolve_mutex    = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  resolve_idle     = PTHREAD_COND_INITIALIZER;

/**
 * cuerpo del hilo de resolución (uno, efímero, por FQDN): corre el
 * `getaddrinfo' bloqueante fuera del loop del selector, deja el resultado en
 * la conexión y la despierta con la notificación de bloqueo (`resolve_done').
 * Recibe una copia mallocada del `selector_key', que es suya y libera.
 *
 * No hay carrera sobre el `socks5': mientras la conexión está en RESOLVING el
 * cliente está en OP_NOOP y el origin_fd no existe, así que ningún evento del
 * selector puede destruirla antes de que la notificación se despache. El hilo
 * toca solo `origin_resolution', `resolve_gai' y `resolve_job' (publicados
 * por el mutex interno de la notificación), y lee `dest_host'/`dest_port',
 * congelados durante el estado. El decremento del contador es la última
 * acción: después de eso el hilo ya no toca memoria compartida.
 */
static void *
resolve_thread(void *arg) {
    struct selector_key *key = arg;
    struct socks5       *s   = ATTACHMENT(key);

    char port_str[6];   // "65535" + '\0'
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)s->dest_port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    // dual-stack: connect_try y el BND del reply soportan ambas familias
    hints.ai_family   = AF_UNSPEC;

    // en fallo getaddrinfo deja el out-param indefinido: se resuelve sobre
    // una local y solo se publica una lista real (liberable).
    struct addrinfo *res = NULL;
    const int gai = getaddrinfo(s->dest_host, port_str, &hints, &res);
    if(gai == 0) {
        s->origin_resolution = res;
    }
    s->resolve_gai = gai;

    selector_notify_block_job(key->s, key->fd, &s->resolve_job);
    free(key);

    pthread_mutex_lock(&resolve_mutex);
    resolve_inflight--;
    pthread_cond_signal(&resolve_idle);
    pthread_mutex_unlock(&resolve_mutex);
    return NULL;
}

/** inicia la resolución del destino FQDN en un hilo aparte */
unsigned
resolve_start(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    s->origin_resolution         = NULL;
    s->origin_resolution_current = NULL;
    // primero OP_NOOP: fija el invariante de RESOLVING (nada puede matar la
    // conexión mientras el hilo corre) antes de que el hilo exista.
    if(selector_set_interest(key->s, s->client_fd, OP_NOOP)
       != SELECTOR_SUCCESS) {
        return ERROR;
    }

    struct selector_key *key_copy = malloc(sizeof(*key_copy));
    if(key_copy == NULL) {
        return connect_fail(s, key->s, SOCKS5_REP_GENERAL_FAILURE);
    }
    *key_copy = *key;

    // detached por atributo: no hay ventana joinable ni un pthread_detach
    // posterior cuyo fallo habría que manejar.
    pthread_attr_t attr;
    if(pthread_attr_init(&attr) != 0) {
        free(key_copy);
        return connect_fail(s, key->s, SOCKS5_REP_GENERAL_FAILURE);
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_mutex_lock(&resolve_mutex);
    resolve_inflight++;
    pthread_mutex_unlock(&resolve_mutex);

    pthread_t tid;
    const int err = pthread_create(&tid, &attr, resolve_thread, key_copy);
    pthread_attr_destroy(&attr);
    if(err != 0) {
        pthread_mutex_lock(&resolve_mutex);
        resolve_inflight--;
        pthread_mutex_unlock(&resolve_mutex);
        free(key_copy);
        return connect_fail(s, key->s, SOCKS5_REP_GENERAL_FAILURE);
    }
    return RESOLVING;
}

void
resolve_shutdown_wait(void) {
    pthread_mutex_lock(&resolve_mutex);
    while(resolve_inflight != 0) {
        pthread_cond_wait(&resolve_idle, &resolve_mutex);
    }
    pthread_mutex_unlock(&resolve_mutex);
}

/**
 * on_block_ready de RESOLVING (sobre client_fd): la resolución terminó y el
 * resultado está en `resolve_gai' / `origin_resolution'. En éxito posiciona
 * el cursor de candidatos y sigue con el connect no bloqueante; en fallo
 * responde el REPLY de error (EAI_* → REP vía `gai_error_to_rep').
 */
unsigned
resolve_done(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    // el server se está apagando: esta conexión quedó salteada por el barrido
    // de cierre (RESOLVING era intocable con el hilo de DNS en vuelo). Cerrarla
    // acá — corre en el hilo principal, ya sincronizado por la notificación —
    // en vez de abrir un connect nuevo que el barrido ya no vería.
    if(socksv5_is_draining()) {
        return ERROR;
    }
    if(s->resolve_gai != 0) {
        return connect_fail(s, key->s, gai_error_to_rep(s->resolve_gai));
    }
    s->origin_resolution_current = s->origin_resolution;
    return connect_try(key);
}

/**
 * completa el BND del reply de éxito con la dirección local del origin_fd
 * (getsockname, RFC 1928 §6): es el endpoint que el kernel le asignó al socket
 * de origen, no el peer remoto. Devuelve ATYP IPv4 o IPv6 según la familia real
 * del socket. Si getsockname falla o la familia no es IPv4/IPv6, degrada a
 * ATYP IPv4 0.0.0.0:0 (la conexión ya está establecida y el BND es informativo,
 * no es un fallo).
 */
static void
connect_reply_bnd(int fd, uint8_t *bnd_atyp, uint8_t bnd_addr[16],
                  uint16_t *bnd_port) {
    struct sockaddr_storage local;
    socklen_t              len = sizeof(local);

    if(getsockname(fd, (struct sockaddr *)&local, &len) == 0) {
        if(local.ss_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)&local;
            *bnd_atyp = SOCKS5_ATYP_IPV4;
            memcpy(bnd_addr, &sin->sin_addr, 4);
            *bnd_port = ntohs(sin->sin_port);
            return;
        }
        if(local.ss_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&local;
            *bnd_atyp = SOCKS5_ATYP_IPV6;
            memcpy(bnd_addr, &sin6->sin6_addr, 16);
            *bnd_port = ntohs(sin6->sin6_port);
            return;
        }
    }
    *bnd_atyp = SOCKS5_ATYP_IPV4;
    memset(bnd_addr, 0, 4);
    *bnd_port = 0;
}

/**
 * on_write_ready de CONNECTING (sobre origin_fd): el connect no bloqueante
 * terminó. SO_ERROR dice si tuvo éxito.
 */
unsigned
connecting(struct selector_key *key) {
    struct socks5     *s = ATTACHMENT(key);
    struct connecting *d = &s->orig.conn;

    int       err = 0;
    socklen_t len = sizeof(err);
    if(getsockopt(s->origin_fd, SOL_SOCKET, SO_ERROR, &err, &len) == -1) {
        // no sabemos el estado real del connect: error interno, no fallo del
        // destino. socksv5_done limpia ambos fds.
        return ERROR;
    }

    if(err == 0) {
        // connect exitoso. Orden que protege el REPLY: primero cortamos eventos
        // del origen, después habilitamos al cliente recién con el REPLY listo.
        if(selector_set_interest(key->s, s->origin_fd, OP_NOOP) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        connect_free_resolution(s);

        char port_str[MAX_PORT_LEN];
        dest_port_str(s->dest_port, port_str);
        metrics_add_user_site(s->username, s->dest_host, port_str, true);

        uint8_t  bnd_atyp;
        uint8_t  bnd_addr[16];
        uint16_t bnd_port;
        connect_reply_bnd(s->origin_fd, &bnd_atyp, bnd_addr, &bnd_port);
        if(request_reply(s, SOCKS5_REP_SUCCEEDED, bnd_atyp, bnd_addr, bnd_port) < 0) {
            return ERROR;
        }
        if(selector_set_interest(key->s, s->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return REQUEST_WRITE;
    }

    // fallo de red en este candidato: verdicto de red (precedencia), probamos
    // el siguiente.
    d->last_error        = err;
    d->had_connect_error = true;
    struct addrinfo *next = (s->origin_resolution_current != NULL)
                                ? s->origin_resolution_current->ai_next
                                : NULL;
    connect_close_origin(s, key->s, true);   // desregistra: references 2 → 1
    s->origin_resolution_current = next;
    if(s->origin_resolution_current != NULL) {
        return connect_try(key);
    }
    return connect_fail(s, key->s, errno_to_rep(d->last_error));
}

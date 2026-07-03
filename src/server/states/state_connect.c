/**
 * state_connect.c -- estado CONNECTING del proxy SOCKSv5 (RFC 1928 §6).
 *
 * Dueño de la resolución del destino (`getaddrinfo', síncrono por ahora) y de
 * la conexión no bloqueante al origen. Inserta un estado CONNECTING entre
 * REQUEST_READ y REQUEST_WRITE: `request_process' hace `return connect_start()'
 * en el camino válido, y cuando el connect termina se manda el REPLY real y se
 * pasa a REQUEST_WRITE.
 *
 * `connect_start' resuelve el destino y arranca un `connect' no bloqueante sobre
 * el origin_fd, que se registra en el selector con interés OP_WRITE; el cliente
 * queda en OP_NOOP hasta que haya REPLY. `connecting' se dispara cuando el origen
 * queda escribible: consulta SO_ERROR y, según el resultado, responde éxito,
 * prueba el siguiente candidato o responde el error.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>        // snprintf
#include <string.h>       // memset, memcpy
#include <unistd.h>       // close
#include <netdb.h>        // getaddrinfo, AI_NUMERICHOST
#include <sys/socket.h>   // socket, connect, getsockopt, getsockname, SO_ERROR
#include <netinet/in.h>   // IPPROTO_TCP, sockaddr_in
#include <arpa/inet.h>    // ntohs

#include "include/state_connect.h"
#include "include/state_request.h"   // request_reply
#include "request_parser.h"          // SOCKS5_ATYP_IPV4, SOCKS5_REP_*
#include "socks5nio.h"               // socks5_handler_ref

/** BND.ADDR de los replies mientras no hay BND real (0.0.0.0) */
static const uint8_t bnd_addr_none[4] = {0, 0, 0, 0};

/**
 * resuelve el destino (dest_host:dest_port) a una lista de `addrinfo' lista
 * para `connect'. Síncrono por ahora: bloquea el loop un instante. Está aislada
 * a propósito para poder moverla a un hilo más adelante sin tocar el resto.
 *
 * Deja la lista en `s->origin_resolution' y el cursor en
 * `s->origin_resolution_current'. Por ahora solo IPv4 y FQDN, por eso el hint
 * `AF_INET' (no `AF_UNSPEC'): con un FQDN con AAAA conectaríamos por IPv6 y el
 * BND, que hoy solo sabe IPv4, degradaría a 0.0.0.0:0.
 *
 * Devuelve el código de retorno de `getaddrinfo' (0 éxito, EAI_* en error).
 */
static int
connect_resolve(struct socks5 *s) {
    char port_str[6];   // "65535" + '\0'
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)s->dest_port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if(s->dest_atyp == SOCKS5_ATYP_IPV4) {
        // el host ya es un literal dotted → sin lookup DNS
        hints.ai_flags |= AI_NUMERICHOST;
    }

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
 * cierra el origin_fd: si `registered' lo desregistra del selector (que es el
 * único decremento de `references') y lo cierra; si no, solo lo cierra. No-op
 * si ya vale -1. Deja siempre origin_fd en -1.
 */
static void
connect_close_origin(struct socks5 *s, fd_selector sel, bool registered) {
    if(s->origin_fd == -1) {
        return;
    }
    if(registered) {
        selector_unregister_fd(sel, s->origin_fd);
    }
    close(s->origin_fd);
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
    return connect_fail(s, key->s, SOCKS5_REP_HOST_UNREACHABLE);
}

/** inicia la resolución + conexión no bloqueante al origen */
unsigned
connect_start(struct selector_key *key) {
    struct socks5     *s = ATTACHMENT(key);
    struct connecting *d = &s->orig.conn;

    d->last_error        = 0;
    d->had_connect_error = false;
    const int gai = connect_resolve(s);
    if(gai != 0) {
        return connect_fail(s, key->s, SOCKS5_REP_HOST_UNREACHABLE);
    }
    return connect_try(key);
}

/**
 * completa el BND del reply de éxito con la dirección local del origin_fd
 * (getsockname, RFC 1928 §6): es el endpoint que el kernel le asignó al socket
 * de origen, no el peer remoto. Si getsockname falla o la familia no es IPv4,
 * degrada a 0.0.0.0:0 (la conexión ya está establecida y el BND es informativo,
 * no es un fallo). Solo IPv4 por ahora.
 */
static void
connect_reply_bnd(int fd, uint8_t *bnd_atyp, uint8_t bnd_addr[4],
                  uint16_t *bnd_port) {
    struct sockaddr_storage local;
    socklen_t              len = sizeof(local);

    *bnd_atyp = SOCKS5_ATYP_IPV4;
    if(getsockname(fd, (struct sockaddr *)&local, &len) == 0
       && local.ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&local;
        memcpy(bnd_addr, &sin->sin_addr, 4);
        *bnd_port = ntohs(sin->sin_port);
        return;
    }
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
        uint8_t  bnd_atyp;
        uint8_t  bnd_addr[4];
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
    return connect_fail(s, key->s, SOCKS5_REP_HOST_UNREACHABLE);
}

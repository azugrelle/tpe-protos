/**
 * state_request.c -- handlers de los estados REQUEST_READ / REQUEST_WRITE del
 * proxy SOCKSv5 (RFC 1928 §4).
 *
 * Lee y parsea el pedido del cliente (CONNECT) y le responde un reply. Todavía
 * no se conecta al origen: el reply de éxito es temporal (BND 0.0.0.0:0) para
 * poder ver el flujo de punta a punta; la conexión real se agrega más adelante.
 */
#include <stdio.h>        // fprintf
#include <sys/socket.h>   // recv, send, MSG_NOSIGNAL

#include "include/state_request.h"

/** BND.ADDR temporal del reply mientras no hay conexión real al origen */
static const uint8_t bnd_addr_none[4] = {0, 0, 0, 0};

/** inicializa el estado REQUEST_READ */
void
request_read_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    d->rb          = &ATTACHMENT(key)->read_buffer;
    d->wb          = &ATTACHMENT(key)->write_buffer;
    d->parser.data = NULL;
    request_parser_init(&d->parser);
}

/** traduce el estado final del parser al código REP de la respuesta */
static uint8_t
request_rep(struct socks5 *s) {
    struct request_parser *p = &s->client.request.parser;

    switch(p->state) {
        case request_done:
            s->dest_atyp = p->atyp;
            s->dest_port = p->dst_port;
            if(request_addr_to_string(p, s->dest_host, sizeof(s->dest_host)) != 0) {
                // destino no representable todavía (p.ej. IPv6).
                return SOCKS5_REP_ATYP_NOT_SUPPORTED;
            }
            fprintf(stderr, "request: CONNECT atyp=%u %s:%u\n",
                    (unsigned)s->dest_atyp, s->dest_host, (unsigned)s->dest_port);
            // éxito temporal: todavía no conectamos al origen.
            return SOCKS5_REP_SUCCEEDED;

        case request_error_unsupported_cmd:
            return SOCKS5_REP_CMD_NOT_SUPPORTED;
        case request_error_unsupported_atyp:
            return SOCKS5_REP_ATYP_NOT_SUPPORTED;
        default:
            return SOCKS5_REP_GENERAL_FAILURE;
    }
}

/** arma el reply en el buffer de escritura y pasa a enviarlo */
static unsigned
request_process(struct selector_key *key) {
    struct socks5     *s = ATTACHMENT(key);
    struct request_st *d = &s->client.request;

    const uint8_t rep = request_rep(s);

    // BND real llega junto con la conexión al origen; por ahora 0.0.0.0:0.
    if(request_marshall(d->wb, rep, SOCKS5_ATYP_IPV4, bnd_addr_none, 0) < 0) {
        return ERROR;
    }
    if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

/** lee y parsea el pedido `request' del cliente */
unsigned
request_read(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n <= 0) {
        return ERROR;
    }
    buffer_write_adv(d->rb, n);

    const enum request_state st = request_consume(d->rb, &d->parser, 0);
    if(!request_is_done(st, 0)) {
        return REQUEST_READ;   // el mensaje todavía no está completo
    }
    return request_process(key);
}

/** envía el reply del `request' al cliente */
unsigned
request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_read_ptr(d->wb, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if(n == -1) {
        return ERROR;
    }
    buffer_read_adv(d->wb, n);
    if(buffer_can_read(d->wb)) {
        return REQUEST_WRITE;   // quedan bytes del reply por enviar
    }
    // terminamos de enviar el reply; todavía no hay relay al origen.
    return DONE;
}

/** cierra el parser al abandonar el estado REQUEST_READ */
void
request_read_close(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    request_parser_close(&d->parser);
}

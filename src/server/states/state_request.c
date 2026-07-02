/**
 * state_request.c -- handler del estado REQUEST_READ del proxy SOCKSv5 (RFC 1928 §4).
 *
 * Lee y parsea el pedido del cliente (CONNECT). Por ahora, una vez parseado el
 * destino se loguea y se cierra la conexión: todavía no se responde el reply ni
 * se conecta al origen.
 */
#include <stdio.h>        // fprintf
#include <sys/socket.h>   // recv

#include "include/state_request.h"

/** inicializa el estado REQUEST_READ */
void
request_read_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    d->rb          = &ATTACHMENT(key)->read_buffer;
    d->wb          = &ATTACHMENT(key)->write_buffer;
    d->parser.data = NULL;
    request_parser_init(&d->parser);
}

/** guarda el destino parseado en la conexión y decide la transición */
static unsigned
request_process(struct socks5 *s) {
    struct request_parser *p = &s->client.request.parser;

    s->dest_atyp = p->atyp;
    s->dest_port = p->dst_port;
    if(request_addr_to_string(p, s->dest_host, sizeof(s->dest_host)) != 0) {
        // destino no representable todavía (p.ej. IPv6): se rechaza.
        return ERROR;
    }

    fprintf(stderr, "request: CONNECT atyp=%u %s:%u\n",
            (unsigned)s->dest_atyp, s->dest_host, (unsigned)s->dest_port);

    // TODO: responder el reply al cliente y conectar al origen antes de cerrar.
    return DONE;
}

/** lee los bytes del pedido `request' y lo alimenta al parser */
unsigned
request_read(struct selector_key *key) {
    struct socks5     *s = ATTACHMENT(key);
    struct request_st *d = &s->client.request;

     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n <= 0) {
        return ERROR;
    }
    buffer_write_adv(d->rb, n);

    bool error = false;
    const enum request_state st = request_consume(d->rb, &d->parser, &error);
    if(!request_is_done(st, 0)) {
        return REQUEST_READ;   // el mensaje todavía no está completo
    }
    if(error) {
        return ERROR;          // pedido inválido o no soportado
    }
    return request_process(s);
}

/** cierra el parser al abandonar el estado REQUEST_READ */
void
request_read_close(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    request_parser_close(&d->parser);
}

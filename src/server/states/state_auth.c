/**
 * state_auth.c -- handler de estados AUTH_READ / AUTH_WRITE del proxy SOCKSv5.
 */
#include <stdint.h>
#include <sys/socket.h>   // recv, send, MSG_NOSIGNAL

#include "include/state_auth.h"
#include "include/state_request.h"          // REQUEST_READ es el próximo estado
#include "utils/include/user_auth_utils.h"  // check_if_valid_credentials

/** inicializa las variables de los estados AUTH_… */
void
auth_read_init(const unsigned state, struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;

    d->rb     = &(ATTACHMENT(key)->read_buffer);
    d->wb     = &(ATTACHMENT(key)->write_buffer);
    d->status = SOCKS_AUTH_STATUS_FAILURE;
    auth_parser_init(&d->parser);
}

/** valida las credenciales recibidas y arma la respuesta del subnegotiation */
static unsigned
auth_process(struct auth_st *d) {
    unsigned ret = AUTH_WRITE;

    d->status = check_if_valid_credentials((const char *) d->parser.username,
                                            (const char *) d->parser.password);
    if(-1 == auth_marshall(d->wb, d->status)) {
        ret = ERROR;
    }
    return ret;
}

/** lee todos los bytes del subnegotiation usuario/contraseña e inicia su proceso */
unsigned
auth_read(struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    unsigned  ret      = AUTH_READ;
        bool  error    = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum auth_state st = auth_consume(d->rb, &d->parser, &error);
        if(auth_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = auth_process(d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/** cierra el parser del auth al abandonar los estados AUTH_… */
void
auth_read_close(const unsigned state, struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    auth_parser_close(&d->parser);
}

/** escribe la respuesta del subnegotiation y transiciona al próximo estado */
unsigned
auth_write(struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;

    unsigned  ret = AUTH_WRITE;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_read_ptr(d->wb, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if(n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->wb, n);
        if(!buffer_can_read(d->wb)) {
            // terminamos de escribir la respuesta del subnegotiation.
            if(SOCKS_AUTH_STATUS_SUCCESS != d->status) {
                // credenciales inválidas: cerramos la conexión (RFC 1929 §2).
                ret = DONE;
            } else if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                ret = REQUEST_READ;
            } else {
                ret = ERROR;
            }
        }
    }
    return ret;
}

/**
 * state_auth.c -- handler de estados AUTH_READ / AUTH_WRITE del proxy SOCKSv5.
 */
#include <stdint.h>
#include <string.h>       // strncpy
#include <sys/socket.h>   // recv, send, MSG_NOSIGNAL

#include "metrics.h"                        // metrics_add_user (usuarios activos)
#include "netutils.h"                       // transient_io_error
#include "include/state_auth.h"
#include "include/state_request.h"          // request_start es el próximo paso
#include "utils/include/user_auth_utils.h"  // check_if_valid_credentials

/** valida las credenciales recibidas y arma la respuesta del subnegotiation */
static unsigned
auth_process(struct selector_key *key) {
    struct socks5  *s   = ATTACHMENT(key);
    struct auth_st *d   = &s->client.auth;
    unsigned        ret = AUTH_WRITE;

    d->status = check_if_valid_credentials((const char *) d->parser.username,
                                            (const char *) d->parser.password);
    if(d->status == SOCKS_AUTH_STATUS_SUCCESS) {
        // queda disponible para el resto de la conexión (p. ej. ACCESS_LOG).
        strncpy(s->username, (const char *) d->parser.username, sizeof(s->username) - 1);
        s->username[sizeof(s->username) - 1] = '\0';
        // alta como usuario activo (comandos USERS/STATS del monitoreo); la
        // baja la hace socks5_destroy al morir la conexión
        metrics_add_user(s->username);
    }
    if(-1 == auth_marshall(d->wb, d->status)) {
        ret = ERROR;
    }
    return ret;
}

/**
 * consume lo que haya en el read_buffer y decide la transición: AUTH_READ si
 * el mensaje sigue incompleto, AUTH_WRITE (vía auth_process) al completarse.
 * Separada del recv para que auth_start pueda procesar bytes que llegaron
 * pipelineados con el hello, por los que no habrá evento de lectura.
 */
static unsigned
auth_consume_buffer(struct selector_key *key) {
    struct auth_st *d     = &ATTACHMENT(key)->client.auth;
    bool            error = false;

    const enum auth_state st = auth_consume(d->rb, &d->parser, &error);
    if(error) {
        return ERROR;
    }
    if(!auth_is_done(st, 0)) {
        return AUTH_READ;
    }
    if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE)) {
        return ERROR;
    }
    return auth_process(key);
}

/**
 * inicia el subnegotiation usuario/contraseña. Es una función de iniciación
 * llamada desde hello_write, no un on_arrival (que no puede transicionar):
 * si el cliente mandó el subnegotiation pegado al hello, esos bytes ya están
 * en el read_buffer y el kernel no va a reportar otro evento de lectura por
 * ellos, así que se procesan acá mismo (puede saltear AUTH_READ).
 */
unsigned
auth_start(struct selector_key *key) {
    struct socks5  *s = ATTACHMENT(key);
    struct auth_st *d = &s->client.auth;

    d->rb     = &s->read_buffer;
    d->wb     = &s->write_buffer;
    d->status = SOCKS_AUTH_STATUS_FAILURE;
    auth_parser_init(&d->parser);

    if(buffer_can_read(d->rb)) {
        const unsigned ret = auth_consume_buffer(key);
        if(AUTH_READ != ret) {
            return ret;
        }
    }
    return (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ))
               ? AUTH_READ : ERROR;
}

/** lee bytes del subnegotiation usuario/contraseña y los procesa */
unsigned
auth_read(struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;

     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n == -1) {
        return transient_io_error() ? AUTH_READ : ERROR;
    }
    if(n == 0) {
        return DONE;   // EOF: el cliente cerró antes de completar el mensaje
    }
    buffer_write_adv(d->rb, n);
    return auth_consume_buffer(key);
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
        if(!transient_io_error()) {
            ret = ERROR;
        }
    } else {
        buffer_read_adv(d->wb, n);
        if(!buffer_can_read(d->wb)) {
            // terminamos de escribir la respuesta del subnegotiation.
            if(SOCKS_AUTH_STATUS_SUCCESS != d->status) {
                // credenciales inválidas: cerramos la conexión (RFC 1929 §2).
                ret = DONE;
            } else {
                // request_start procesa inline un REQUEST que haya llegado
                // pipelineado con el subnegotiation.
                ret = request_start(key);
            }
        }
    }
    return ret;
}

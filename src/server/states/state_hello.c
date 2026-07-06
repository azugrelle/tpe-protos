/**
 * state_hello.c -- handler de estados HELLO_READ / HELLO_WRITE del proxy SOCKSv5.
 */
#include <stdint.h>
#include <sys/socket.h>   // recv, send, MSG_NOSIGNAL

#include "include/state_hello.h"
#include "include/state_auth.h"      // auth_start es el próximo paso si se autentica
#include "include/state_request.h"   // request_start es el próximo paso si no
#include "utils/include/user_auth_utils.h" 

/** callback del parser utilizado en `hello_read' */
static void
on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected  = p->data;

    if(SOCKS_HELLO_USERNAME_PASSWORD == method && auth_is_required()) {
        // preferido si el cliente lo ofrece y hay tabla de usuarios contra
        // la cual validar, sin importar el orden.
        *selected = method;
    } else if(SOCKS_HELLO_NOAUTHENTICATION_REQUIRED == method
              && !auth_is_required()) {
        // si no se exige auth, no-auth siempre gana: elegir user/pass sin
        // usuarios cargados garantiza que la autenticación falle siempre.
        *selected = method;
    }
}

/** inicializa las variables de los estados HELLO_… */
void
hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    d->rb                              = &(ATTACHMENT(key)->read_buffer);
    d->wb                              = &(ATTACHMENT(key)->write_buffer);
    d->method                          = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;
    d->parser.data                     = &d->method;
    d->parser.on_authentication_method = on_hello_method, hello_parser_init(
            &d->parser);
}

/** procesamiento del mensaje `hello' */
static unsigned
hello_process(const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;

    // el METHOD de la respuesta es el método elegido tal cual (0x00, 0x02 o
    // 0xFF si ninguno fue aceptable); ver RFC 1928 §3.
    if (-1 == hello_marshall(d->wb, d->method)) {
        ret = ERROR;
    }
    // Si el método es "no aceptable" igual pasamos por HELLO_WRITE para
    // enviar el 0xFF; recién ahí cerramos (lo maneja hello_write → DONE).
    return ret;
}

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
unsigned
hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned  ret      = HELLO_READ;
        bool  error    = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if(hello_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = hello_process(d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/** cierra el parser del hello al abandonar los estados HELLO_… */
void
hello_read_close(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    hello_parser_close(&d->parser);
}

/** escribe la respuesta del `hello' y transiciona al próximo estado */
unsigned
hello_write(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    unsigned  ret = HELLO_WRITE;
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
            // terminamos de escribir la respuesta del hello. La iniciación
            // del paso siguiente procesa inline lo que el cliente haya
            // mandado pipelineado junto al hello (por esos bytes no va a
            // haber otro evento de lectura).
            if(SOCKS_HELLO_NO_ACCEPTABLE_METHODS == d->method) {
                // ya enviamos 0xFF: cerramos la conexión (RFC 1928 §3).
                ret = DONE;
            } else if(SOCKS_HELLO_USERNAME_PASSWORD == d->method) {
                // el cliente eligió autenticarse: sigue el subnegotiation.
                ret = auth_start(key);
            } else {
                ret = request_start(key);
            }
        }
    }
    return ret;
}

/**
 * hello.c -- parser del mensaje HELLO de SOCKSv5 (RFC 1928 §3).
 *
 * Ver hello.h para la descripción del formato y del contrato.
 */
#include <stdio.h>
#include <stdlib.h>  // abort

#include "hello.h"

void
hello_parser_init(struct hello_parser *p) {
    p->state     = hello_version;
    p->remaining = 0;
}

enum hello_state
hello_parser_feed(struct hello_parser *p, const uint8_t b) {
    switch(p->state) {
        case hello_version:
            // VER debe ser 0x05; si no, se rechaza el saludo.
            if(0x05 == b) {
                p->state = hello_nmethods;
            } else {
                p->state = hello_error_unsupported_version;
            }
            break;

        case hello_nmethods:
            // cantidad de métodos que el cliente ofrece a continuación.
            p->remaining = b;
            if(p->remaining == 0) {
                p->state = hello_done;
            } else {
                p->state = hello_methods;
            }
            break;

        case hello_methods:
            // un método más ofrecido: se lo notificamos al usuario.
            if(p->on_authentication_method != NULL) {
                p->on_authentication_method(p, b);
            }
            p->remaining--;
            if(p->remaining == 0) {
                p->state = hello_done;
            }
            break;

        case hello_done:
        case hello_error_unsupported_version:
            // estados terminales: no consumen más bytes.
            break;

        default:
            fprintf(stderr, "hello_parser_feed: estado desconocido %d\n",
                    p->state);
            abort();
    }
    return p->state;
}

bool
hello_is_done(const enum hello_state state, bool *errored) {
    bool ret;
    switch(state) {
        case hello_error_unsupported_version:
            if(errored != NULL) {
                *errored = true;
            }
            ret = true;
            break;
        case hello_done:
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
    return ret;
}

enum hello_state
hello_consume(buffer *b, struct hello_parser *p, bool *errored) {
    enum hello_state st = p->state;
    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = hello_parser_feed(p, c);
        if(hello_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

void
hello_parser_close(struct hello_parser *p) {
    // nada que liberar por ahora.
}

int
hello_marshall(buffer *b, const uint8_t method) {
    size_t   n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 2) {
        return -1;
    }
    buff[0] = 0x05;    // VER
    buff[1] = method;  // METHOD elegido
    buffer_write_adv(b, 2);
    return 2;
}

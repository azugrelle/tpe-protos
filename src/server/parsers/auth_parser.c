/**
 * auth_parser.c -- parser del subnegotiation usuario/contraseña de
 * SOCKSv5 (RFC 1929 §2).
 *
 * Ver auth_parser.h para la descripción del formato y del contrato.
 */
#include <stdio.h>
#include <stdlib.h>  // abort

#include "include/auth_parser.h"

void
auth_parser_init(struct auth_parser *p) {
    p->state       = auth_version;
    p->remaining   = 0;
    p->ulen        = 0;
    p->uname_read  = 0;
    p->plen        = 0;
    p->passwd_read = 0;
}

enum auth_state
auth_parser_feed(struct auth_parser *p, const uint8_t b) {
    switch(p->state) {
        case auth_version:
            // VER debe ser 0x01; si no, se rechaza el subnegotiation.
            if(SOCKS_AUTH_VERSION == b) {
                p->state = auth_ulen;
            } else {
                p->state = auth_error_unsupported_version;
            }
            break;

        case auth_ulen:
            // cantidad de bytes de UNAME que vienen a continuación.
            p->ulen       = b;
            p->uname_read = 0;
            if(p->ulen == 0) {
                // ULEN=0: username vacío, no hay bytes de UNAME que leer.
                p->username[0] = '\0';
                p->state = auth_plen;
            } else {
                p->remaining = p->ulen;
                p->state     = auth_uname;
            }
            break;

        case auth_uname:
            if(b == '\0') {
                p->state = auth_error_embedded_nul;
                break;
            }
            p->username[p->uname_read++] = b;
            p->remaining--;
            if(p->remaining == 0) {
                p->username[p->uname_read] = '\0';
                p->state = auth_plen;
            }
            break;

        case auth_plen:
            // cantidad de bytes de PASSWD que vienen a continuación.
            p->plen        = b;
            p->passwd_read = 0;
            if(p->plen == 0) {
                // PLEN=0: password vacío.
                p->password[0] = '\0';
                p->state = auth_done;
            } else {
                p->remaining = p->plen;
                p->state     = auth_passwd;
            }
            break;

        case auth_passwd:
            if(b == '\0') {
                p->state = auth_error_embedded_nul;
                break;
            }
            p->password[p->passwd_read++] = b;
            p->remaining--;
            if(p->remaining == 0) {
                p->password[p->passwd_read] = '\0';
                p->state = auth_done;
            }
            break;

        case auth_done:
        case auth_error_unsupported_version:
        case auth_error_embedded_nul:
            // estados terminales: no consumen más bytes.
            break;

        default:
            fprintf(stderr, "auth_parser_feed: estado desconocido %d\n",
                    p->state);
            abort();
    }
    return p->state;
}

bool
auth_is_done(const enum auth_state state, bool *errored) {
    bool ret;
    switch(state) {
        case auth_error_unsupported_version:
        case auth_error_embedded_nul:
            if(errored != NULL) {
                *errored = true;
            }
            ret = true;
            break;
        case auth_done:
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
    return ret;
}

enum auth_state
auth_consume(buffer *b, struct auth_parser *p, bool *errored) {
    enum auth_state st = p->state;
    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = auth_parser_feed(p, c);
        if(auth_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

void
auth_parser_close(struct auth_parser *p) {
    // nada que liberar por ahora.
}

int
auth_marshall(buffer *b, const uint8_t status) {
    size_t   n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 2) {
        return -1;
    }
    buff[0] = SOCKS_AUTH_VERSION;  // VER del subnegotiation
    buff[1] = status;              // STATUS
    buffer_write_adv(b, 2);
    return 2;
}

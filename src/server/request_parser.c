/**
 * request_parser.c -- parser del mensaje REQUEST de SOCKSv5 (RFC 1928 §4).
 *
 * Ver request_parser.h para la descripción del formato y del contrato.
 */
#include <stdio.h>
#include <stdlib.h>  // abort
#include <string.h>  // memcpy
#include <arpa/inet.h>  // inet_ntop

#include "request_parser.h"

void
request_parser_init(struct request_parser *p) {
    p->state         = request_version;
    p->remaining     = 0;
    p->cmd           = 0;
    p->atyp          = 0;
    p->dst_addr_len  = 0;
    p->dst_addr_read = 0;
    p->dst_port      = 0;
}

enum request_state
request_parser_feed(struct request_parser *p, const uint8_t b) {
    switch(p->state) {
        case request_version:
            // VER debe ser 0x05; si no, se rechaza el pedido.
            if(SOCKS5_VERSION == b) {
                p->state = request_cmd;
            } else {
                p->state = request_error_unsupported_version;
            }
            break;

        case request_cmd:
            // solo CONNECT está soportado; el resto se rechaza con REP 0x07.
            p->cmd = b;
            if(SOCKS5_REQ_CMD_CONNECT == b) {
                p->state = request_rsv;
            } else {
                p->state = request_error_unsupported_cmd;
            }
            break;

        case request_rsv:
            // RSV es reservado: se lee y se ignora su valor.
            p->state = request_atyp;
            break;

        case request_atyp:
            // el tipo de dirección define cuántos bytes mide DST.ADDR.
            p->atyp          = b;
            p->dst_addr_read = 0;
            if(SOCKS5_ATYP_IPV4 == b) {
                p->remaining = SOCKS5_IPV4_ADDR_LEN;
                p->state     = request_dstaddr;
            } else if(SOCKS5_ATYP_IPV6 == b) {
                p->remaining = SOCKS5_IPV6_ADDR_LEN;
                p->state     = request_dstaddr;
            } else if(SOCKS5_ATYP_DOMAIN == b) {
                // falta leer el byte de longitud antes del nombre.
                p->state = request_dstaddr_fqdn_len;
            } else {
                p->state = request_error_unsupported_atyp;
            }
            break;

        case request_dstaddr_fqdn_len:
            // byte de longitud: cuántos octetos de nombre siguen.
            p->remaining     = b;
            p->dst_addr_read = 0;
            if(p->remaining == 0) {
                // un FQDN vacío no es resoluble: se rechaza el pedido.
                p->state = request_error_invalid;
            } else {
                p->state = request_dstaddr;
            }
            break;

        case request_dstaddr:
            // se acumulan los octetos de DST.ADDR hasta completar el largo.
            p->dst_addr[p->dst_addr_read++] = b;
            if(--p->remaining == 0) {
                p->dst_addr_len = p->dst_addr_read;
                p->remaining    = SOCKS5_PORT_LEN;
                p->state        = request_dstport;
            }
            break;

        case request_dstport:
            // DST.PORT viene en big-endian: primero el byte alto, luego el bajo.
            p->dst_port = (uint16_t)((p->dst_port << 8) | b);
            if(--p->remaining == 0) {
                p->state = request_done;
            }
            break;

        case request_done:
        case request_error_unsupported_version:
        case request_error_unsupported_cmd:
        case request_error_unsupported_atyp:
        case request_error_invalid:
            // estados terminales: no consumen más bytes.
            break;

        default:
            fprintf(stderr, "request_parser_feed: estado desconocido %d\n",
                    p->state);
            abort();
    }
    return p->state;
}

bool
request_is_done(const enum request_state state, bool *errored) {
    bool ret;
    switch(state) {
        case request_error_unsupported_version:
        case request_error_unsupported_cmd:
        case request_error_unsupported_atyp:
        case request_error_invalid:
            if(errored != NULL) {
                *errored = true;
            }
            ret = true;
            break;
        case request_done:
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
    return ret;
}

enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored) {
    enum request_state st = p->state;
    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = request_parser_feed(p, c);
        if(request_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

void
request_parser_close(struct request_parser *p) {
    // nada que liberar por ahora.
}

int
request_addr_to_string(const struct request_parser *p, char *out, size_t outlen) {
    if(SOCKS5_ATYP_IPV4 == p->atyp) {
        return inet_ntop(AF_INET, p->dst_addr, out, (socklen_t)outlen) == NULL
               ? -1 : 0;
    }
    if(SOCKS5_ATYP_DOMAIN == p->atyp) {
        if((size_t)p->dst_addr_len + 1 > outlen) {  // +1 por el NUL
            return -1;
        }
        memcpy(out, p->dst_addr, p->dst_addr_len);
        out[p->dst_addr_len] = '\0';
        return 0;
    }
    // IPv6 (u otro): reconstrucción pendiente para T52.
    return -1;
}

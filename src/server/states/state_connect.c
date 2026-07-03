/**
 * state_connect.c -- estado CONNECTING del proxy SOCKSv5 (RFC 1928 §6).
 *
 * Dueño de la resolución del destino (`getaddrinfo', síncrono por ahora) y de
 * la conexión no bloqueante al origen. Inserta un estado CONNECTING entre
 * REQUEST_READ y REQUEST_WRITE: `request_process' hace `return connect_start()'
 * en el camino válido, y cuando el connect termina se manda el REPLY real y se
 * pasa a REQUEST_WRITE.
 *
 * Por ahora es un esqueleto: los dos puntos de entrada existen y compilan, pero
 * todavía nadie los referencia (el enum y la tabla de estados se agregan en el
 * paso siguiente) ni resuelven/conectan de verdad.
 */
#include <stdio.h>        // snprintf
#include <string.h>       // memset
#include <netdb.h>        // getaddrinfo, AI_NUMERICHOST
#include <netinet/in.h>   // IPPROTO_TCP

#include "include/state_connect.h"
#include "include/state_request.h"   // request_reply
#include "request_parser.h"          // SOCKS5_ATYP_IPV4, SOCKS5_REP_*

/** BND.ADDR de los replies mientras no hay BND real (0.0.0.0); paso 7 lo llena */
static const uint8_t bnd_addr_none[4] = {0, 0, 0, 0};

/**
 * resuelve el destino (dest_host:dest_port) a una lista de `addrinfo' lista
 * para `connect'. Síncrono por ahora: bloquea el loop un instante (T50 lo mueve
 * a un hilo sin tocar el resto). Aislada a propósito para eso.
 *
 * Deja la lista en `s->origin_resolution' y el cursor en
 * `s->origin_resolution_current'. Alcance T40: IPv4 + FQDN (IPv6 → T52), por eso
 * el hint `AF_INET' (no `AF_UNSPEC'): con AAAA primero conectaríamos por IPv6 y
 * el BND, que hoy solo sabe IPv4, degradaría a 0.0.0.0:0.
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

/** inicia la resolución + conexión no bloqueante al origen */
unsigned
connect_start(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    // Stub temporal (paso 5): todavía no resolvemos ni abrimos sockets — el
    // connect real es el paso 6, que cablea connect_resolve. Por ahora un CONNECT
    // recibe un REPLY de error honesto (sin hang ni abort) para cerrar el flujo.
    (void)connect_resolve;
    if(request_reply(s, SOCKS5_REP_GENERAL_FAILURE, SOCKS5_ATYP_IPV4,
                     bnd_addr_none, 0) < 0) {
        return ERROR;
    }
    // fd nombrado (no _key): la STM es compartida y connect_start correrá también
    // desde origin_fd en el paso 6 (D-018 · fd explícito).
    if(selector_set_interest(key->s, s->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

/** se dispara cuando el origen queda escribible: el connect terminó */
unsigned
connecting(struct selector_key *key) {
    // TODO: getsockopt(SO_ERROR), armar el REPLY y pasar a REQUEST_WRITE.
    return DONE;
}

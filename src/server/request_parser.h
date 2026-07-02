#ifndef REQUEST_H_zX8cV4bN2mK6qW9tR1yU7iO3pL5aS0dF
#define REQUEST_H_zX8cV4bN2mK6qW9tR1yU7iO3pL5aS0dF

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"

/*
 * request_parser.c / request_parser.h -- parser del mensaje REQUEST de SOCKSv5
 * (RFC 1928 §4). No sabe nada de sockets ni de la stm.
 *
 * El pedido del cliente tiene la forma:
 *
 *   +----+-----+-------+------+----------+----------+
 *   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *   | 1  |  1  | 0x00  |  1   | Variable |    2     |
 *   +----+-----+-------+------+----------+----------+
 *
 * DST.ADDR es de largo variable según ATYP:
 *   - IPv4  (0x01): 4 octetos.
 *   - DOMAIN(0x03): 1 octeto de longitud N, seguido de N octetos (sin NUL).
 *   - IPv6  (0x04): 16 octetos.
 * DST.PORT son 2 octetos en network byte order (big-endian).
 *
 * Igual que el HELLO, el mensaje puede llegar fragmentado: el parser consume
 * byte a byte y mantiene su estado entre llamadas. No se sabe cuántos bytes
 * mide DST.ADDR hasta leer ATYP (y, si es FQDN, hasta leer el byte de longitud).
 */

/** versión del protocolo (RFC 1928) */
static const uint8_t SOCKS5_VERSION = 0x05;

/** comandos (CMD). Para el TP solo se soporta CONNECT (RFC 1928 §4). */
static const uint8_t SOCKS5_REQ_CMD_CONNECT       = 0x01;
static const uint8_t SOCKS5_REQ_CMD_BIND          = 0x02;
static const uint8_t SOCKS5_REQ_CMD_UDP_ASSOCIATE = 0x03;

/** tipos de dirección (ATYP). IPv6 se parsea pero se completa en T52. */
static const uint8_t SOCKS5_ATYP_IPV4   = 0x01;
static const uint8_t SOCKS5_ATYP_DOMAIN = 0x03;
static const uint8_t SOCKS5_ATYP_IPV6   = 0x04;

/*
 * Códigos de respuesta (REP) del reply, RFC 1928 §6. En M1 (T21) solo se usan
 * SUCCEEDED (éxito temporal para inspección), CMD_NOT_SUPPORTED y
 * ATYP_NOT_SUPPORTED; el resto los usa el connect real en T40/T52.
 */
static const uint8_t SOCKS5_REP_SUCCEEDED           = 0x00;
static const uint8_t SOCKS5_REP_GENERAL_FAILURE     = 0x01;
static const uint8_t SOCKS5_REP_CONN_NOT_ALLOWED    = 0x02;
static const uint8_t SOCKS5_REP_NETWORK_UNREACHABLE = 0x03;
static const uint8_t SOCKS5_REP_HOST_UNREACHABLE    = 0x04;
static const uint8_t SOCKS5_REP_CONN_REFUSED        = 0x05;
static const uint8_t SOCKS5_REP_TTL_EXPIRED         = 0x06;
static const uint8_t SOCKS5_REP_CMD_NOT_SUPPORTED   = 0x07;
static const uint8_t SOCKS5_REP_ATYP_NOT_SUPPORTED  = 0x08;

/** longitud máxima de un FQDN (byte de longitud → 255) + NUL de comodidad */
#define SOCKS5_FQDN_MAX_LEN 256

/** estados del parser del REQUEST */
enum request_state {
    /** esperando el byte de versión (debe ser 0x05) */
    request_version,
    /** esperando el comando (CMD); solo CONNECT es soportado */
    request_cmd,
    /** esperando el byte reservado (RSV); se lee y se ignora */
    request_rsv,
    /** esperando el tipo de dirección (ATYP), que define cómo sigue DST.ADDR */
    request_atyp,
    /** solo FQDN: byte de longitud N que precede al nombre */
    request_dstaddr_fqdn_len,
    /** leyendo los N octetos de DST.ADDR (4 IPv4 / 16 IPv6 / N FQDN) */
    request_dstaddr,
    /** leyendo los 2 octetos de DST.PORT (big-endian) */
    request_dstport,

    // estados terminales
    request_done,
    request_error_unsupported_version,
    request_error_unsupported_cmd,
    request_error_unsupported_atyp,
};

/**
 * salida del parser: el destino ya parseado (crudo). La reconstrucción a
 * string legible / sockaddr (para el connect de T40) la hace el handler del
 * estado a partir de `atyp` + `dst_addr`.
 */
struct request_parser {
    /** dato provisto por el usuario, disponible para simetría con hello */
    void *data;

    /** estado actual del parser */
    enum request_state state;
    /** bytes que todavía faltan leer del campo actual (DST.ADDR o DST.PORT) */
    uint8_t remaining;

    /** comando pedido (RFC 1928 §4) */
    uint8_t cmd;
    /** tipo de dirección del destino */
    uint8_t atyp;

    /**
     * DST.ADDR crudo, sin interpretar:
     *   - IPv4: 4 octetos de la IP.
     *   - IPv6: 16 octetos de la IP.
     *   - FQDN: los `dst_addr_len' octetos del nombre (sin NUL).
     */
    uint8_t dst_addr[SOCKS5_FQDN_MAX_LEN];
    /** cantidad de octetos válidos en `dst_addr' */
    uint8_t dst_addr_len;
    /** índice de escritura dentro de `dst_addr' mientras se acumula */
    uint8_t dst_addr_read;

    /** DST.PORT ya reconstruido a host byte order */
    uint16_t dst_port;
};

/** inicializa el parser dejándolo en el estado inicial */
void request_parser_init(struct request_parser *p);

/** entrega un byte al parser y retorna el nuevo estado */
enum request_state request_parser_feed(struct request_parser *p, const uint8_t b);

/**
 * consume los bytes disponibles en el buffer `b' alimentando el parser.
 * Se detiene si el parser llega a un estado terminal o si se agotan los datos.
 * Si `errored' no es NULL, se pone en true ante un error de parseo.
 */
enum request_state request_consume(buffer *b, struct request_parser *p, bool *errored);

/**
 * retorna true si `state' es un estado terminal. Si es un estado de error y
 * `errored' no es NULL, deja *errored en true.
 */
bool request_is_done(const enum request_state state, bool *errored);

/** libera los recursos del parser (no hay nada que liberar por ahora) */
void request_parser_close(struct request_parser *p);

/**
 * escribe el reply del REQUEST en el buffer `b' (RFC 1928 §6):
 *
 *   +----+-----+-------+------+----------+----------+
 *   |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *   +----+-----+-------+------+----------+----------+
 *
 * `bnd_atyp' define el largo de `bnd_addr' (4 para IPv4, 16 para IPv6).
 * `bnd_port' se escribe en network byte order. Retorna la cantidad de bytes
 * escritos, o -1 si no había espacio suficiente en el buffer.
 */
int request_marshall(buffer *b, const uint8_t rep, const uint8_t bnd_atyp,
                     const uint8_t *bnd_addr, const uint16_t bnd_port);

/*
 * `struct request_st' -- estado de la conexión durante REQUEST_READ/WRITE.
 * Vive en la `union' de estados de `struct socks5' (ver socks5_state.h).
 * Agrupa los buffers de I/O (heredados del `struct socks5') y la instancia
 * del parser, igual que `struct hello_st' con `hello_parser'.
 */
struct request_st {
    /** buffers de I/O (heredados del `struct socks5') */
    buffer                *rb, *wb;
    /** parser del mensaje REQUEST */
    struct request_parser  parser;
};

#endif

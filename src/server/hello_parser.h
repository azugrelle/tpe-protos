#ifndef HELLO_H_kQmN2sR8vT5xZ1aB7cD3eF6gH9jL0pW
#define HELLO_H_kQmN2sR8vT5xZ1aB7cD3eF6gH9jL0pW

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"

/*
 * hello_parser.c / hello_parser.h -- parser del mensaje HELLO de SOCKSv5 (RFC 1928 §3). No sabe nada de sockets ni de la stm.
 *
 * El saludo del cliente tiene la forma:
 *
 *   +----+----------+----------+
 *   |VER | NMETHODS | METHODS  |
 *   | 1  |    1     | 1 a 255  |
 *   +----+----------+----------+
 *
 * El mensaje puede llegar fragmentado (un `recv' puede traer solo una parte).
 * Por eso el parser consume byte a byte y mantiene su estado entre llamadas:
 * mientras falten bytes devuelve un estado "no terminado", y el llamador lo
 * vuelve a alimentar cuando llegan más datos.
 */

/** métodos de autenticación relevantes para M1 (RFC 1928 §3) */
static const uint8_t SOCKS_HELLO_NOAUTHENTICATION_REQUIRED = 0x00;
static const uint8_t SOCKS_HELLO_NO_ACCEPTABLE_METHODS     = 0xFF;

/** estados del parser del HELLO */
enum hello_state {
    /** esperando el byte de versión (debe ser 0x05) */
    hello_version,
    /** esperando la cantidad de métodos ofrecidos */
    hello_nmethods,
    /** leyendo los `nmethods' bytes de métodos */
    hello_methods,

    // estados terminales
    hello_done,
    hello_error_unsupported_version,
};

struct hello_parser {
    /** dato provisto por el usuario, disponible en el callback */
    void *data;
    /** invocado una vez por cada método ofrecido por el cliente */
    void (*on_authentication_method)(struct hello_parser *parser,
                                     const uint8_t method);

    /** estado actual del parser */
    enum hello_state state;
    /** cantidad de bytes de METHODS que todavía faltan leer */
    uint8_t remaining;
};

/** inicializa el parser dejándolo en el estado inicial */
void hello_parser_init(struct hello_parser *p);

/** entrega un byte al parser y retorna el nuevo estado */
enum hello_state hello_parser_feed(struct hello_parser *p, const uint8_t b);

/**
 * consume los bytes disponibles en el buffer `b' alimentando el parser.
 * Se detiene si el parser llega a un estado terminal o si se agotan los datos.
 * Si `errored' no es NULL, se pone en true ante un error de parseo.
 */
enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored);

/**
 * retorna true si `state' es un estado terminal. Si es un estado de error y
 * `errored' no es NULL, deja *errored en true.
 */
bool hello_is_done(const enum hello_state state, bool *errored);

/** libera los recursos del parser (no hay nada que liberar por ahora) */
void hello_parser_close(struct hello_parser *p);

/**
 * escribe la respuesta del HELLO ( VER=0x05 | METHOD ) en el buffer `b'.
 * Retorna la cantidad de bytes escritos (2) o -1 si no había espacio.
 */
int hello_marshall(buffer *b, const uint8_t method);

#endif

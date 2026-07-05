#ifndef AUTH_H_gT4rW1yB8nK6vQ2sZ9pL5cX0dF7jH3m
#define AUTH_H_gT4rW1yB8nK6vQ2sZ9pL5cX0dF7jH3m

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"

/*
 * auth_parser.c / auth_parser.h -- parser del subnegotiation de
 * usuario/contraseña de SOCKSv5 (RFC 1929 §2). No sabe nada de sockets ni
 * de la stm.
 *
 * El mensaje del cliente tiene la forma:
 *
 *   +----+------+----------+------+----------+
 *   |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *   | 1  |  1   | 1 a 255  |  1   | 1 a 255  |
 *   +----+------+----------+------+----------+
 *
 * A diferencia del HELLO (una lista homogénea de métodos, uno por byte, con
 * un callback por ítem), acá el mensaje es una estructura fija de 4 campos:
 * no hay nada útil que notificar hasta no tener el mensaje completo, así
 * que el parser simplemente acumula UNAME/PASSWD en sus propios buffers
 * (mismo criterio que ya usa `request_parser.h' para el REQUEST).
 */

/** versión del subnegotiation de usuario/contraseña (RFC 1929 §2) */
static const uint8_t SOCKS_AUTH_VERSION = 0x01;

/** STATUS de la respuesta (RFC 1929 §2): 0x00 éxito, cualquier otro valor es falla */
static const uint8_t SOCKS_AUTH_STATUS_SUCCESS = 0x00;
static const uint8_t SOCKS_AUTH_STATUS_FAILURE = 0x01;

/**
 * ULEN/PLEN son 1 byte (0 a 255); el +1 es para poder null-terminar incluso
 * un campo de 255 bytes. No tiene relación con el límite de almacenamiento
 * de `user_auth_utils.c' (ENTRY_LENGTH = 255).
 */
#define SOCKS_AUTH_MAX_LEN 256

/** estados del parser del subnegotiation usuario/contraseña */
enum auth_state {
    /** esperando el byte de versión (debe ser 0x01) */
    auth_version,
    /** esperando ULEN */
    auth_ulen,
    /** leyendo los `ulen' bytes de UNAME */
    auth_uname,
    /** esperando PLEN */
    auth_plen,
    /** leyendo los `plen' bytes de PASSWD */
    auth_passwd,

    // estados terminales
    auth_done,
    auth_error_unsupported_version,
};

struct auth_parser {
    /** estado actual del parser */
    enum auth_state state;
    /** bytes que faltan leer del campo actual (UNAME o PASSWD) */
    uint8_t remaining;

    /** UNAME acumulado, null-terminado al completarse el campo */
    uint8_t username[SOCKS_AUTH_MAX_LEN];
    uint8_t ulen;
    uint8_t uname_read;

    /** PASSWD acumulado, null-terminado al completarse el campo */
    uint8_t password[SOCKS_AUTH_MAX_LEN];
    uint8_t plen;
    uint8_t passwd_read;
};

/** inicializa el parser dejándolo en el estado inicial */
void auth_parser_init(struct auth_parser *p);

/** entrega un byte al parser y retorna el nuevo estado */
enum auth_state auth_parser_feed(struct auth_parser *p, const uint8_t b);

/**
 * consume los bytes disponibles en el buffer `b' alimentando el parser.
 * Se detiene si el parser llega a un estado terminal o si se agotan los datos.
 * Si `errored' no es NULL, se pone en true ante un error de parseo.
 */
enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *errored);

/**
 * retorna true si `state' es un estado terminal. Si es un estado de error y
 * `errored' no es NULL, deja *errored en true.
 */
bool auth_is_done(const enum auth_state state, bool *errored);

/** libera los recursos del parser (no hay nada que liberar por ahora) */
void auth_parser_close(struct auth_parser *p);

/**
 * escribe la respuesta del subnegotiation ( VER=0x01 | STATUS ) en el
 * buffer `b'. Retorna la cantidad de bytes escritos (2) o -1 si no había
 * espacio.
 */
int auth_marshall(buffer *b, const uint8_t status);

#endif

#ifndef SOCKS5_STATE_H_tW7bQ2mR9kX4cZ1nV5pL8sH3dF6gJ0aY
#define SOCKS5_STATE_H_tW7bQ2mR9kX4cZ1nV5pL8sH3dF6gJ0aY

/*
 * socks5_state.h -- definiciones internas compartidas por la máquina de
 * estados del proxy SOCKSv5.
 *
 * Este header lo incluyen tanto `socks5nio.c' (dueño del ciclo de vida de la
 * conexión y de la tabla de estados) como cada uno de los `states/state_*.c'
 * (que implementan los handlers de un estado). Acá viven:
 *   - el enum de estados,
 *   - los structs por-estado y el `struct socks5' que los agrupa,
 *   - los macros de acceso (`ATTACHMENT', `N').
 *
 * Los prototipos de los handlers de cada estado viven en su propio
 * `states/include/state_*.h'.
 */

#include <stdint.h>
#include <sys/socket.h>   // sockaddr_storage
#include <netdb.h>        // addrinfo

#include "buffer.h"
#include "stm.h"

#include "hello_parser.h"
#include "auth_parser.h"
#include "request_parser.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

/** máquina de estados general de una conexión cliente ↔ proxy */
enum socks_v5state {
    /**
     * recibe el mensaje `hello` del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no esté completo
     *   - HELLO_WRITE cuando está completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    HELLO_READ,

    /**
     * envía la respuesta del `hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    HELLO_WRITE,

    /**
     * recibe el subnegotiation usuario/contraseña del cliente (RFC 1929 §2)
     * y lo valida contra la tabla de usuarios cargada por -u.
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - AUTH_READ  mientras el mensaje no esté completo
     *   - AUTH_WRITE cuando está completo
     *   - ERROR      ante cualquier error (IO/parseo)
     */
    AUTH_READ,

    /**
     * envía la respuesta del subnegotiation (VER|STATUS) al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - AUTH_WRITE   mientras queden bytes por enviar
     *   - REQUEST_READ cuando el STATUS fue éxito (0x00)
     *   - DONE         cuando el STATUS fue falla (RFC 1929 exige cerrar
     *                  la conexión ante autenticación fallida)
     *   - ERROR        ante cualquier error (IO)
     */
    AUTH_WRITE,

    /**
     * recibe el pedido `request' del cliente.
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_READ  mientras el mensaje no esté completo
     *   - REQUEST_WRITE cuando se parseó el pedido (para responder el reply)
     *   - ERROR         ante error de IO
     */
    REQUEST_READ,

    /**
     * envía el reply del `request' al cliente (RFC 1928 §6).
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_WRITE mientras queden bytes por enviar
     *   - DONE          cuando se envió el reply (todavía no se conecta al origen)
     *   - ERROR         ante error de IO
     */
    REQUEST_WRITE,

    // estados terminales
    DONE,
    ERROR,
};

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;
    struct hello_parser   parser;
    /** el método de autenticación seleccionado */
    uint8_t               method;
};

/** usado por AUTH_READ, AUTH_WRITE */
struct auth_st {
    /** buffer utilizado para I/O (los mismos del `struct socks5') */
    buffer              *rb, *wb;
    struct auth_parser   parser;
    /** resultado de check_if_valid_credentials: 0x00 éxito, 0x01 falla */
    uint8_t              status;
};

/* `struct request_st' (usado por REQUEST_READ) se declara en request_parser.h */

/** usado por el estado CONNECTING (conexión no bloqueante al origin server) */
struct connecting {
    /** buffer de escritura donde se arma el REPLY (el mismo del `struct socks5') */
    buffer  *wb;
    /** código REP del reply, calculado según el resultado del connect (RFC 1928 §6) */
    uint8_t  reply;
    /** errno del último candidato fallido, preservado para traducirlo a REP */
    int      last_error;
};

/** usado por COPY / relay bidireccional */
struct copy {
    int placeholder;
};

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {
    /** información de la conexión con el cliente */
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len;
    int                           client_fd;

    /**
     * destino pedido en el REQUEST (RFC 1928 §4), parseado en REQUEST_READ.
     * Lo consume la resolución/conexión al origen.
     *   - dest_atyp: ATYP del pedido (IPv4 / FQDN / IPv6).
     *   - dest_host: DST.ADDR ya reconstruido a texto (IPv4 dotted o FQDN).
     *   - dest_port: DST.PORT en host byte order.
     */
    uint8_t                       dest_atyp;
    char                          dest_host[SOCKS5_FQDN_MAX_LEN];
    uint16_t                      dest_port;

    /** resolución del origin server (DNS async); se libera al destruir */
    struct addrinfo              *origin_resolution;
    /** información de la conexión con el origin server */
    struct sockaddr_storage       origin_addr;
    socklen_t                     origin_addr_len;
    int                           origin_fd;

    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct hello_st           hello;
        struct auth_st            auth;
        struct request_st         request;
        struct copy               copy;
    } client;
    /** estados para el origin_fd */
    union {
        struct connecting         conn;
        struct copy               copy;
    } orig;

    /** buffers crudos y sus vistas para I/O */
    uint8_t                       raw_buff_a[2048], raw_buff_b[2048];
    buffer                        read_buffer, write_buffer;

    /** cantidad de referencias a este objeto; si es 1 se destruye */
    unsigned                      references;

    /** siguiente en el pool de reuso */
    struct socks5                *next;
};

/** obtiene el struct (socks5 *) desde la llave de selección */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

#endif

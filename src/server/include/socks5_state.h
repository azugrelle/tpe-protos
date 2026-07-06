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

#include <stdbool.h>
#include <stdint.h>
#include <time.h>         // time_t
#include <sys/socket.h>   // sockaddr_storage
#include <netdb.h>        // addrinfo

#include "buffer.h"
#include "selector.h"
#include "stm.h"

#include "parsers/include/hello_parser.h"
#include "parsers/include/auth_parser.h"
#include "parsers/include/request_parser.h"

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
     *   - RESOLVING     pedido válido con FQDN (la resolución va a un hilo)
     *   - CONNECTING    pedido válido con IP literal (connect en vuelo)
     *   - REQUEST_WRITE pedido inválido o fallo inmediato (REPLY de error listo)
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
     *   - COPY          si el REPLY enviado fue de éxito (arranca el relay)
     *   - DONE          si el REPLY fue de error (RFC 1928 §6: se cierra)
     *   - ERROR         ante error de IO
     */
    REQUEST_WRITE,

    /**
     * espera el resultado de la resolución DNS del destino (FQDN), que corre
     * en un hilo aparte para no bloquear el loop del selector.
     *
     * Intereses:
     *     - OP_NOOP sobre client_fd (no hay I/O que esperar: la salida del
     *       estado es la notificación de bloqueo, no un evento de fd)
     *     - origin_fd todavía no existe
     *
     * Transiciones (desde on_block_ready, en el hilo principal):
     *   - RESOLVING     mientras el hilo de resolución no notifique
     *   - CONNECTING    la resolución tuvo éxito y hay un connect en vuelo
     *   - REQUEST_WRITE la resolución (o todos los candidatos) falló y el
     *                   REPLY de error quedó listo
     *   - ERROR         ante un error interno irrecuperable
     */
    RESOLVING,

    /**
     * espera a que termine el `connect' no bloqueante al origin server.
     *
     * Intereses:
     *     - OP_WRITE sobre origin_fd (el connect terminó cuando queda escribible)
     *     - OP_NOOP  sobre client_fd (todavía no hay REPLY ni relay)
     *
     * Transiciones:
     *   - CONNECTING    mientras el connect siga en vuelo
     *   - REQUEST_WRITE cuando se conoce el resultado (éxito o fallo) y hay REPLY
     *   - ERROR         ante un error interno irrecuperable
     */
    CONNECTING,

    /**
     * relay bidireccional cliente↔origen: el proxy ya no inspecciona el
     * tráfico, copia crudo en ambos sentidos sobre los buffers.
     *
     * Intereses (recomputados tras cada I/O — así se implementa el
     * backpressure, sobre ambos fds):
     *     - OP_READ  sobre un fd si su buffer destino tiene lugar
     *     - OP_WRITE sobre un fd si su buffer fuente tiene datos
     *
     * Soporta half-close: un EOF apaga solo ese sentido y el otro sigue
     * copiando; el FIN se propaga (shutdown SHUT_WR) al drenar los bytes en
     * vuelo.
     *
     * Transiciones:
     *   - COPY  mientras algún sentido siga activo
     *   - DONE  cuando ambos sentidos vieron EOF y los buffers se vaciaron
     *   - ERROR ante un error de I/O real o un fallo del selector
     */
    COPY,

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
    /**
     * true si `last_error' proviene de un fallo de connect() (verdicto de red).
     * Tiene precedencia sobre los fallos de socket()/nio (recurso local) al
     * elegir el REP, y persiste entre reintentos de distintos candidatos.
     */
    bool     had_connect_error;
};

/**
 * usado por COPY / relay bidireccional. Hay una instancia por fd (una en
 * `client.copy', otra en `orig.copy'), cruzadas entre sí vía `other': el
 * buffer donde un lado deposita lo que lee es el que el otro lado drena.
 */
struct copy {
    /** el fd de este lado (apunta a client_fd u origin_fd del `struct socks5') */
    int          *fd;
    /** buffer donde este fd deposita lo que lee (lo escribe el otro lado) */
    buffer       *rb;
    /** buffer del que este fd toma lo que escribe (lo llena el otro lado) */
    buffer       *wb;
    /** sentidos todavía activos de este lado (OP_READ y/o OP_WRITE) */
    fd_interest   duplex;
    /** el otro lado del relay */
    struct copy  *other;
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

    /**
     * REP del último REPLY serializado (lo deja `request_reply'). Decide la
     * transición al drenar REQUEST_WRITE: éxito → COPY (arranca el relay),
     * error → DONE (RFC 1928 §6: tras un reply de error se cierra).
     */
    uint8_t                       reply_rep;

    /**
     * resolución del destino, lista para `connect'. Para un FQDN la deja el
     * hilo de DNS antes de notificar (RESOLVING); para literales la deja
     * `connect_resolve' inline. Se libera al destruir.
     */
    /** usuario autenticado (RFC1929) o "anonymous" si no hubo auth */
    char                          username[SOCKS_AUTH_MAX_LEN];

    /** resolución del origin server (DNS async); se libera al destruir */
    struct addrinfo              *origin_resolution;
    /**
     * rc del `getaddrinfo' corrido en el hilo de DNS (0 éxito, EAI_* en
     * error). Lo escribe el hilo antes de notificar; lo lee `resolve_done'
     * en el hilo principal.
     */
    int                           resolve_gai;
    /**
     * aviso de notificación de bloqueo del hilo de DNS, siempre embebido
     * (`heap' queda en false por el memset de `socks5_new'). Hay a lo sumo
     * una resolución en vuelo por conexión, así que se reusa.
     */
    struct blocking_job           resolve_job;
    /** cursor (borrowed) dentro de origin_resolution; NULL si no hay/agotado */
    struct addrinfo              *origin_resolution_current;
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

    /**
     * buffers crudos de I/O (heap) y sus vistas. El tamaño lo fija la config
     * al crear la conexión: las nuevas nacen con el valor vigente de
     * `buf_size'; las vivas conservan el suyo hasta morir (realojar buffers
     * con datos en vuelo no tiene nada a favor).
     */
    uint8_t                      *raw_buff_a, *raw_buff_b;
    size_t                        buf_size;
    buffer                        read_buffer, write_buffer;

    /**
     * instante de la última actividad (cualquier evento despachado a la
     * conexión), en segundos de CLOCK_MONOTONIC — reloj de pared no: un salto
     * de NTP cerraría conexiones sanas en masa o dejaría zombies inmunes.
     * Lo compara el barrido de inactividad contra el timeout de la config.
     */
    time_t                        last_activity;

    /** cantidad de referencias a este objeto; si es 1 se destruye */
    unsigned                      references;

    /** siguiente en el pool de reuso */
    struct socks5                *next;

    /**
     * lista intrusiva de conexiones vivas (doblemente enlazada, separada de
     * `next': una estructura está en una lista o en la otra, nunca en ambas).
     * Permite saber cuántas conexiones siguen activas durante el drenado.
     */
    struct socks5                *live_next, *live_prev;
};

/** obtiene el struct (socks5 *) desde la llave de selección */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

#endif

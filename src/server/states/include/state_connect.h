#ifndef STATE_CONNECT_H_hJ4dF6gK0aY2wR8tN1mB5cX3vZ7qL9sP
#define STATE_CONNECT_H_hJ4dF6gK0aY2wR8tN1mB5cX3vZ7qL9sP

/*
 * state_connect.h -- estados RESOLVING y CONNECTING del proxy SOCKSv5
 * (RFC 1928 §6).
 *
 * Con el REQUEST ya validado (REQUEST_READ), este módulo es el dueño de la
 * resolución del destino (`getaddrinfo') y de la conexión no bloqueante al
 * origen: `state_request.c' solo valida el pedido, no resuelve DNS ni abre
 * sockets. La resolución de un FQDN corre en un hilo aparte (estado
 * RESOLVING); los literales IPv4/IPv6 se resuelven inline porque no hay
 * lookup de red.
 *
 * A propósito NO hay un `connecting_init': la iniciación de la conexión no
 * puede vivir en un `on_arrival' porque este devuelve `void' y no puede
 * transicionar. Por eso el disparador es `connect_start', llamado desde
 * `request_process', que devuelve el próximo estado.
 */

#include "include/socks5_state.h"
#include "selector.h"

/**
 * inicia la resolución del destino y la conexión no bloqueante al origen.
 *
 * Se llama desde `request_process' (no es un handler de la stm). Devuelve el
 * próximo estado: CONNECTING si el connect quedó en vuelo, o REQUEST_WRITE con
 * un REPLY de error si falló de entrada.
 */
unsigned connect_start(struct selector_key *key);

/**
 * inicia la resolución del destino FQDN. La llama `connect_start' cuando el
 * pedido trae ATYP DOMAINNAME (no es un handler de la stm). Devuelve el
 * próximo estado: RESOLVING con la resolución en vuelo, o REQUEST_WRITE con
 * un REPLY de error si no se pudo arrancar.
 */
unsigned resolve_start(struct selector_key *key);

/**
 * handler on_block_ready de RESOLVING, sobre client_fd: se dispara en el hilo
 * principal cuando el hilo de resolución notificó que terminó. Levanta el
 * resultado (`resolve_gai' / `origin_resolution') y sigue con el connect al
 * origen, o responde el REPLY de error.
 */
unsigned resolve_done(struct selector_key *key);

/**
 * espera a que no quede ningún hilo de resolución vivo. Llamarla al salir del
 * loop del selector y ANTES de destruir el selector, las conexiones o el
 * pool: un hilo tardío escribiría sobre memoria liberada y notificaría sobre
 * un mutex destruido. Con ninguna resolución en vuelo retorna de inmediato.
 */
void resolve_shutdown_wait(void);

/**
 * handler on_write_ready de CONNECTING, sobre origin_fd: se dispara cuando el
 * selector marca al origen como escribible (el connect no bloqueante terminó).
 */
unsigned connecting(struct selector_key *key);

#endif

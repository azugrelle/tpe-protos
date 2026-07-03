#ifndef STATE_CONNECT_H_hJ4dF6gK0aY2wR8tN1mB5cX3vZ7qL9sP
#define STATE_CONNECT_H_hJ4dF6gK0aY2wR8tN1mB5cX3vZ7qL9sP

/*
 * state_connect.h -- estado CONNECTING del proxy SOCKSv5 (RFC 1928 §6).
 *
 * Con el REQUEST ya validado (REQUEST_READ), este módulo es el dueño de la
 * resolución del destino (`getaddrinfo') y de la conexión no bloqueante al
 * origen: `state_request.c' solo valida el pedido, no resuelve DNS ni abre
 * sockets.
 *
 * Tiene dos puntos de entrada, y a propósito NO hay un `connecting_init':
 * la iniciación de la conexión no puede vivir en un `on_arrival' porque este
 * devuelve `void' y no puede transicionar. Por eso el disparador es
 * `connect_start', llamado desde `request_process', que devuelve el próximo
 * estado.
 */

#include "socks5_state.h"
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
 * handler on_write_ready de CONNECTING, sobre origin_fd: se dispara cuando el
 * selector marca al origen como escribible (el connect no bloqueante terminó).
 */
unsigned connecting(struct selector_key *key);

#endif

#ifndef STATE_REQUEST_H_zX8cV4bN2mK6qW9tR1yU7iO3pL5aS0dG
#define STATE_REQUEST_H_zX8cV4bN2mK6qW9tR1yU7iO3pL5aS0dG

/*
 * state_request.h -- handler del estado REQUEST_READ (RFC 1928 §4).
 */

#include "socks5_state.h"
#include "selector.h"

/** inicializa el estado REQUEST_READ (on_arrival) */
void request_read_init(const unsigned state, struct selector_key *key);

/** lee y parsea el pedido `request' del cliente */
unsigned request_read(struct selector_key *key);

/** cierra el parser al abandonar el estado (on_departure) */
void request_read_close(const unsigned state, struct selector_key *key);

#endif

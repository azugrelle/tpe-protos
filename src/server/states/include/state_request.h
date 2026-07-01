#ifndef STATE_REQUEST_H_zX8cV4bN2mK6qW9tR1yU7iO3pL5aS0dG
#define STATE_REQUEST_H_zX8cV4bN2mK6qW9tR1yU7iO3pL5aS0dG

/*
 * state_request.h -- handler del estado REQUEST_READ (RFC 1928 §4).
 *
 * Stub para M1: cierra la conexión. El parseo real del REQUEST llega en T21.
 */

#include "socks5_state.h"
#include "selector.h"

/** lee el pedido `request' del cliente (stub M1: cierra la conexión) */
unsigned request_read(struct selector_key *key);

#endif

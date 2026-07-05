#ifndef STATE_REQUEST_H_zX8cV4bN2mK6qW9tR1yU7iO3pL5aS0dG
#define STATE_REQUEST_H_zX8cV4bN2mK6qW9tR1yU7iO3pL5aS0dG

/*
 * state_request.h -- handler del estado REQUEST_READ (RFC 1928 §4).
 */

#include "include/socks5_state.h"
#include "selector.h"

/** inicializa el estado REQUEST_READ (on_arrival) */
void request_read_init(const unsigned state, struct selector_key *key);

/**
 * serializa el reply del REQUEST (RFC 1928 §6) en `s->write_buffer'. Único punto
 * de serialización del reply: los errores pasan IPv4/0.0.0.0/0 y el éxito el BND
 * real. Devuelve <0 si el reply no entra en el buffer.
 */
int request_reply(struct socks5 *s, uint8_t rep, uint8_t bnd_atyp,
                  const uint8_t *bnd_addr, uint16_t bnd_port);

/** lee y parsea el pedido `request' del cliente */
unsigned request_read(struct selector_key *key);

/** envía el reply del `request' al cliente */
unsigned request_write(struct selector_key *key);

/** cierra el parser al abandonar el estado (on_departure) */
void request_read_close(const unsigned state, struct selector_key *key);

#endif

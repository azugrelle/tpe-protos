#ifndef STATE_COPY_H_qN3vB7xK1mT5cJ9wF2hR6yL8sD4gP0aZ
#define STATE_COPY_H_qN3vB7xK1mT5cJ9wF2hR6yL8sD4gP0aZ

/*
 * state_copy.h -- estado COPY del proxy SOCKSv5: relay bidireccional
 * cliente↔origen.
 *
 * Con el REPLY de éxito ya entregado (REQUEST_WRITE), el proxy deja de
 * inspeccionar el tráfico y copia bytes crudos en ambos sentidos, en streaming
 * sobre los buffers de la conexión.
 *
 * Igual que con CONNECTING, a propósito NO hay un `copy_init' (on_arrival):
 * la activación inicial de intereses puede fallar y `on_arrival' devuelve
 * `void', así que no podría transicionar a ERROR. El punto de entrada es
 * `copy_start', llamado desde `request_write', que devuelve el próximo estado.
 */

#include "socks5_state.h"
#include "selector.h"

/**
 * arma el relay: cablea los dos `struct copy' (uno por fd, cruzados) y setea
 * los intereses iniciales de ambos fds. Se llama desde `request_write' tras
 * drenar el REPLY de éxito (no es un handler de la stm). Devuelve COPY, o
 * ERROR si el selector falla.
 */
unsigned copy_start(struct selector_key *key);

/** handler on_read_ready de COPY; key->fd puede ser client_fd u origin_fd */
unsigned copy_r(struct selector_key *key);

/** handler on_write_ready de COPY; key->fd puede ser client_fd u origin_fd */
unsigned copy_w(struct selector_key *key);

#endif

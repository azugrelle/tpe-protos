#ifndef SOCKS5NIO_H_pR3tQ9vW1kZ7bN5xM2cH8dF4gL6jS0aY
#define SOCKS5NIO_H_pR3tQ9vW1kZ7bN5xM2cH8dF4gL6jS0aY

#include "selector.h"

/** handler de aceptación de una nueva conexión entrante al proxy */
void
socksv5_passive_accept(struct selector_key *key);

/**
 * referencia al handler de eventos del selector, compartido por el client_fd y
 * el origin_fd de una misma conexión. Lo usa el estado CONNECTING al registrar
 * el origin_fd en el selector.
 */
const fd_handler *
socks5_handler_ref(void);

/** libera el pool de estructuras `socks5' reutilizables */
void
socksv5_pool_destroy(void);

#endif

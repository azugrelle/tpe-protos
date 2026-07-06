#ifndef SOCKS5NIO_H_pR3tQ9vW1kZ7bN5xM2cH8dF4gL6jS0aY
#define SOCKS5NIO_H_pR3tQ9vW1kZ7bN5xM2cH8dF4gL6jS0aY

#include <stdbool.h>

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

/** cantidad de conexiones SOCKS5 vivas (para el drenado del apagado) */
unsigned
socksv5_live_count(void);

/**
 * activa el modo drenado del apagado: las resoluciones de DNS que terminen
 * después cierran su conexión en vez de avanzar al connect del origen.
 */
void
socksv5_start_draining(void);

bool
socksv5_is_draining(void);

/**
 * cierra las conexiones en estados de handshake/conexión (sin transferencia
 * útil que drenar). No toca COPY (se drena) ni RESOLVING (el hilo de DNS
 * sigue en vuelo; esa conexión se cierra al notificar, por el modo drenado).
 */
void
socksv5_shutdown_handshakes(fd_selector s);

/**
 * cierra las conexiones sin actividad hace más del timeout de la config
 * (leído en cada pasada: un CONFIG timeout nuevo aplica a todas las vivas).
 * Lo llama el loop principal en cada vuelta; la granularidad la da el
 * select_timeout del selector. No toca RESOLVING (hilo de DNS en vuelo).
 */
void
socksv5_sweep_timeouts(fd_selector s);

#endif

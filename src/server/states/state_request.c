/**
 * state_request.c -- estado REQUEST_READ del proxy SOCKSv5 (RFC 1928 §4).
 *
 * Stub para M1: cierra limpio la conexión. El parseo real llega en T21.
 */
#include "include/state_request.h"

/** stub del estado REQUEST_READ para M1; el parseo real llega en T21 */
unsigned
request_read(struct selector_key *key) {
    // Todavía no procesamos el request: cerramos limpio la conexión.
    return DONE;
}

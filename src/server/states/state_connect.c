/**
 * state_connect.c -- estado CONNECTING del proxy SOCKSv5 (RFC 1928 §6).
 *
 * Dueño de la resolución del destino (`getaddrinfo', síncrono por ahora) y de
 * la conexión no bloqueante al origen. Inserta un estado CONNECTING entre
 * REQUEST_READ y REQUEST_WRITE: `request_process' hace `return connect_start()'
 * en el camino válido, y cuando el connect termina se manda el REPLY real y se
 * pasa a REQUEST_WRITE.
 *
 * Por ahora es un esqueleto: los dos puntos de entrada existen y compilan, pero
 * todavía nadie los referencia (el enum y la tabla de estados se agregan en el
 * paso siguiente) ni resuelven/conectan de verdad.
 */
#include "include/state_connect.h"

/** inicia la resolución + conexión no bloqueante al origen */
unsigned
connect_start(struct selector_key *key) {
    // TODO: resolver el destino y arrancar el connect no bloqueante.
    return REQUEST_WRITE;
}

/** se dispara cuando el origen queda escribible: el connect terminó */
unsigned
connecting(struct selector_key *key) {
    // TODO: getsockopt(SO_ERROR), armar el REPLY y pasar a REQUEST_WRITE.
    return DONE;
}

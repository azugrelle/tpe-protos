#ifndef STATE_AUTH_H_nR6wE2tY9qA4kM1pJ8vL3sD7fH0cX5b
#define STATE_AUTH_H_nR6wE2tY9qA4kM1pJ8vL3sD7fH0cX5b

/*
 * state_auth.h -- handlers de los estados AUTH_READ / AUTH_WRITE.
 *
 * El subnegotiation usuario/contraseña de SOCKSv5 (RFC 1929 §2) se lee y
 * responde acá. El parseo byte a byte lo hace el parser dedicado de
 * `auth_parser.c'.
 */

#include "include/socks5_state.h"
#include "selector.h"

/**
 * inicia el subnegotiation usuario/contraseña (iniciación llamada desde
 * hello_write, no un on_arrival): prepara AUTH_READ y procesa inline los
 * bytes que hayan llegado pipelineados con el hello. Devuelve el próximo
 * estado (puede saltear AUTH_READ).
 */
unsigned auth_start(struct selector_key *key);

/** lee los bytes del subnegotiation y, cuando está completo, responde */
unsigned auth_read(struct selector_key *key);

/** cierra el parser del auth al abandonar los estados AUTH_… */
void auth_read_close(const unsigned state, struct selector_key *key);

/** escribe la respuesta del subnegotiation y transiciona al próximo estado */
unsigned auth_write(struct selector_key *key);

#endif

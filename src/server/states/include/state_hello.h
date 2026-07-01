#ifndef STATE_HELLO_H_pL3sD0fA6nH2kP9wR4tY7uJ1cX5vZ8qB
#define STATE_HELLO_H_pL3sD0fA6nH2kP9wR4tY7uJ1cX5vZ8qB

/*
 * state_hello.h -- handlers de los estados HELLO_READ / HELLO_WRITE.
 *
 * El saludo SOCKSv5 (RFC 1928 §3) se lee y responde acá. El parseo byte a
 * byte lo hace el parser dedicado de `hello.c'.
 */

#include "socks5_state.h"
#include "selector.h"

/** inicializa las variables del estado al entrar a HELLO_READ */
void hello_read_init(const unsigned state, struct selector_key *key);

/** lee los bytes del mensaje `hello' y, cuando está completo, responde */
unsigned hello_read(struct selector_key *key);

/** cierra el parser del hello al abandonar los estados HELLO_… */
void hello_read_close(const unsigned state, struct selector_key *key);

/** escribe la respuesta del `hello' y transiciona al próximo estado */
unsigned hello_write(struct selector_key *key);

#endif

#ifndef NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U
#define NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "buffer.h"

/**
 * true si el -1 de un recv/send es transitorio y no debe matar la conexión:
 * select puede reportar un fd como listo y que la operación igual falle con
 * EAGAIN/EWOULDBLOCK (man 2 select, BUGS), y EINTR es un corte por señal.
 * Con un selector level-triggered alcanza con permanecer en el mismo estado
 * y esperar el próximo evento.
 */
static inline bool
transient_io_error(void) {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

#define SOCKADDR_TO_HUMAN_MIN (INET6_ADDRSTRLEN + 5 + 1)
/**
 * Describe de forma humana un sockaddr:
 *
 * @param buff     el buffer de escritura
 * @param buffsize el tamaño del buffer  de escritura
 *
 * @param af    address family
 * @param addr  la dirección en si
 * @param nport puerto en network byte order
 *
 */
const char *
sockaddr_to_human(char *buff, const size_t buffsize,
                  const struct sockaddr *addr);



/**
 * Escribe n bytes de buff en fd de forma bloqueante
 *
 * Retorna 0 si se realizó sin problema y errno si hubo problemas
 */
int
sock_blocking_write(const int fd, buffer *b);


/**
 * copia todo el contenido de source a dest de forma bloqueante.
 *
 * Retorna 0 si se realizó sin problema y errno si hubo problemas
 */
int
sock_blocking_copy(const int source, const int dest);

#endif

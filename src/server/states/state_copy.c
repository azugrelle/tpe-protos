/**
 * state_copy.c -- estado COPY del proxy SOCKSv5: relay bidireccional
 * cliente↔origen.
 *
 * Dos flujos independientes sobre buffers de tamaño fijo, cada uno con su
 * `struct copy': `read_buffer' lleva cliente→origen y `write_buffer'
 * origen→cliente (cruzados vía `other'). Nunca se acumula el mensaje entero:
 * se copia en streaming, leyendo hasta llenar el buffer y escribiendo lo que
 * se pueda.
 *
 * El backpressure sale del recomputo de intereses tras cada I/O
 * (`copy_compute_interests'): un fd solo interesa para lectura si su buffer
 * destino tiene lugar, y para escritura si su buffer fuente tiene datos. Un
 * buffer lleno apaga OP_READ del lado que lo llena hasta que el otro lo drene,
 * así un extremo lento no hace crecer la memoria.
 *
 * El mismo handler atiende eventos de ambos fds (el `socks5_handler' y la stm
 * son únicos por conexión): `copy_ptr' resuelve de qué lado vino el evento y
 * el resto del código es simétrico.
 *
 * Por ahora un EOF de cualquier lado termina la conexión completa (DONE); el
 * half-close (shutdown diferido, un sentido sobrevive al otro) llega después.
 */
#include <errno.h>
#include <sys/socket.h>   // recv, send, MSG_NOSIGNAL

#include "include/state_copy.h"

/** ¿el evento vino del cliente o del origen? */
static struct copy *
copy_ptr(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    return (key->fd == s->client_fd) ? &s->client.copy : &s->orig.copy;
}

/**
 * recomputa el interés de un lado según sus sentidos activos y el estado de
 * sus buffers: OP_READ si hay lugar donde depositar, OP_WRITE si hay datos
 * que escribir. Acá vive el backpressure.
 */
static selector_status
copy_compute_interests(fd_selector sel, struct copy *d) {
    fd_interest interest = OP_NOOP;

    if((d->duplex & OP_READ) && buffer_can_write(d->rb)) {
        interest |= OP_READ;
    }
    if((d->duplex & OP_WRITE) && buffer_can_read(d->wb)) {
        interest |= OP_WRITE;
    }
    return selector_set_interest(sel, *d->fd, interest);
}

/**
 * recomputa los intereses de ambos lados: cada I/O sobre un buffer puede
 * habilitar o apagar eventos del otro fd (destino con lugar ⇒ el lector
 * vuelve a leer; fuente con datos ⇒ el escritor despierta).
 */
static bool
copy_refresh_interests(struct selector_key *key, struct copy *d) {
    return copy_compute_interests(key->s, d)        == SELECTOR_SUCCESS
        && copy_compute_interests(key->s, d->other) == SELECTOR_SUCCESS;
}

unsigned
copy_start(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct copy   *c = &s->client.copy;
    struct copy   *o = &s->orig.copy;

    c->fd     = &s->client_fd;
    c->rb     = &s->read_buffer;    // lo que el cliente manda, hacia el origen
    c->wb     = &s->write_buffer;   // lo que el origen mandó, hacia el cliente
    c->duplex = OP_READ | OP_WRITE;
    c->other  = o;

    o->fd     = &s->origin_fd;
    o->rb     = &s->write_buffer;
    o->wb     = &s->read_buffer;
    o->duplex = OP_READ | OP_WRITE;
    o->other  = c;

    // intereses iniciales: el cliente pierde el OP_WRITE del REPLY (su wb
    // quedó vacío) y el origen sale del OP_NOOP en que lo dejó CONNECTING;
    // si el cliente mandó bytes pegados al REQUEST, ya están en read_buffer
    // y encienden el OP_WRITE del origen sin ningún recv previo.
    if(!copy_refresh_interests(key, c)) {
        return ERROR;
    }
    return COPY;
}

unsigned
copy_r(struct selector_key *key) {
    struct copy *d = copy_ptr(key);

     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    if(count == 0) {
        // evento espurio con el buffer destino lleno: recv de 0 bytes
        // devolvería 0 y se confundiría con EOF. Recomputar y seguir.
        return copy_refresh_interests(key, d) ? COPY : ERROR;
    }

    n = recv(key->fd, ptr, count, 0);
    if(n == -1) {
        if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            // no es error: el selector es level-triggered y redispara.
            return COPY;
        }
        return ERROR;
    }
    if(n == 0) {
        // EOF: por ahora cierra la conexión completa (half-close después).
        return DONE;
    }

    buffer_write_adv(d->rb, n);
    return copy_refresh_interests(key, d) ? COPY : ERROR;
}

unsigned
copy_w(struct selector_key *key) {
    struct copy *d = copy_ptr(key);

     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_read_ptr(d->wb, &count);
    if(count == 0) {
        // evento espurio con el buffer fuente vacío: nada que enviar.
        return copy_refresh_interests(key, d) ? COPY : ERROR;
    }

    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if(n == -1) {
        if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return COPY;
        }
        return ERROR;
    }

    buffer_read_adv(d->wb, n);
    return copy_refresh_interests(key, d) ? COPY : ERROR;
}

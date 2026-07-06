#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <check.h>

// se incluye el .c para poder probar sus funciones estáticas
// (copy_compute_interests) sin linkear selector.c: los símbolos externos que
// referencia el módulo se satisfacen con stubs propios (abajo). recv/send se
// interceptan con --wrap para inyectar errno sin depender del kernel, y
// shutdown para contar propagaciones del FIN e inyectar sus fallos.
#include "states/state_copy.c"

//////////////////////////////////////////////////////////////////////
// Stubs de los símbolos externos que referencia state_copy.c, gobernados por
// globals para observar efectos e inyectar fallos. `reset_injection' los deja
// en su valor neutro.

#define FD_TRACK 128

static fd_interest g_interest[FD_TRACK];      // último interés seteado por fd
static int         g_setinterest_calls     = 0;
static int         g_setinterest_fail_from = 0;   // falla desde la llamada N (1-based); 0 = nunca
static int         g_recv_calls            = 0;
static int         g_recv_inject_errno     = 0;   // recv devuelve -1 con este errno; 0 = real
static int         g_send_calls            = 0;
static int         g_send_inject_errno     = 0;   // send devuelve -1 con este errno; 0 = real
static int         g_shutdown_rd_calls     = 0;
static int         g_shutdown_wr_calls     = 0;
static bool        g_shutdown_rd_fail      = false;
static bool        g_shutdown_wr_fail      = false;

static void
reset_injection(void) {
    memset(g_interest, 0xFF, sizeof(g_interest));  // 0xFF = "nunca seteado"
    g_setinterest_calls     = 0;
    g_setinterest_fail_from = 0;
    g_recv_calls            = 0;
    g_recv_inject_errno     = 0;
    g_send_calls            = 0;
    g_send_inject_errno     = 0;
    g_shutdown_rd_calls     = 0;
    g_shutdown_wr_calls     = 0;
    g_shutdown_rd_fail      = false;
    g_shutdown_wr_fail      = false;
}

selector_status
selector_set_interest(fd_selector s, int fd, fd_interest i) {
    (void)s;
    g_setinterest_calls++;
    if(g_setinterest_fail_from != 0
       && g_setinterest_calls >= g_setinterest_fail_from) {
        return SELECTOR_IO;
    }
    if(fd >= 0 && fd < FD_TRACK) {
        g_interest[fd] = i;
    }
    return SELECTOR_SUCCESS;
}

extern ssize_t __real_recv(int fd, void *buf, size_t len, int flags);

ssize_t
__wrap_recv(int fd, void *buf, size_t len, int flags) {
    g_recv_calls++;
    if(g_recv_inject_errno != 0) {
        errno = g_recv_inject_errno;
        return -1;
    }
    return __real_recv(fd, buf, len, flags);
}

extern ssize_t __real_send(int fd, const void *buf, size_t len, int flags);

ssize_t
__wrap_send(int fd, const void *buf, size_t len, int flags) {
    g_send_calls++;
    if(g_send_inject_errno != 0) {
        errno = g_send_inject_errno;
        return -1;
    }
    return __real_send(fd, buf, len, flags);
}

extern int __real_shutdown(int fd, int how);

int
__wrap_shutdown(int fd, int how) {
    if(how == SHUT_RD) {
        g_shutdown_rd_calls++;
        if(g_shutdown_rd_fail) {
            errno = ENOTCONN;
            return -1;
        }
    } else if(how == SHUT_WR) {
        g_shutdown_wr_calls++;
        if(g_shutdown_wr_fail) {
            errno = ENOTCONN;
            return -1;
        }
    }
    return __real_shutdown(fd, how);
}

//////////////////////////////////////////////////////////////////////
// Harness: un `struct socks5' con socketpairs reales como cliente y origen.
// El lado "local" de cada par es el fd del proxy; el "peer" simula al cliente
// o al origin server remoto.

struct test_conn {
    struct socks5 s;
    // respaldo de los buffers de I/O: en el server viven en el heap
    // (dimensionados por la config); el harness los provee embebidos
    uint8_t       buff_a[2048], buff_b[2048];
    int           client_peer;
    int           origin_peer;
};

static void
conn_init(struct test_conn *t) {
    int c[2], o[2];
    ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, c));
    ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, o));

    memset(&t->s, 0, sizeof(t->s));
    t->s.client_fd = c[0];
    t->client_peer = c[1];
    t->s.origin_fd = o[0];
    t->origin_peer = o[1];
    // los fds del proxy son no bloqueantes, como en el server real
    ck_assert_int_ne(-1, fcntl(t->s.client_fd, F_SETFL, O_NONBLOCK));
    ck_assert_int_ne(-1, fcntl(t->s.origin_fd, F_SETFL, O_NONBLOCK));

    t->s.raw_buff_a = t->buff_a;
    t->s.raw_buff_b = t->buff_b;
    t->s.buf_size   = sizeof(t->buff_a);
    buffer_init(&t->s.read_buffer,  t->s.buf_size, t->s.raw_buff_a);
    buffer_init(&t->s.write_buffer, t->s.buf_size, t->s.raw_buff_b);
}

static void
conn_close(struct test_conn *t) {
    close(t->s.client_fd);
    close(t->client_peer);
    close(t->s.origin_fd);
    close(t->origin_peer);
}

static struct selector_key
key_for(struct test_conn *t, int fd) {
    struct selector_key key = { .s = NULL, .fd = fd, .data = &t->s };
    return key;
}

/* deja `n' bytes ya depositados en un buffer (como si alguien los hubiera leído) */
static void
buffer_preload(buffer *b, const uint8_t *data, size_t n) {
    size_t  space;
    uint8_t *ptr = buffer_write_ptr(b, &space);
    ck_assert_uint_ge(space, n);
    memcpy(ptr, data, n);
    buffer_write_adv(b, n);
}

//////////////////////////////////////////////////////////////////////
// copy_start: cableado e intereses iniciales

START_TEST (test_start_wires_and_sets_initial_interests) {
    // la costura más delicada: el cliente venía en OP_WRITE por el REPLY y el
    // origen en OP_NOOP. Con ambos buffers vacíos los dos deben quedar SOLO
    // con OP_READ (el OP_WRITE obsoleto del cliente desaparece).
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);

    reset_injection();
    unsigned st = copy_start(&key);

    ck_assert_uint_eq(COPY, st);
    ck_assert_uint_eq(OP_READ, g_interest[t.s.client_fd]);
    ck_assert_uint_eq(OP_READ, g_interest[t.s.origin_fd]);

    // cableado cruzado: el rb de un lado es el wb del otro
    struct copy *c = &t.s.client.copy;
    struct copy *o = &t.s.orig.copy;
    ck_assert_ptr_eq(&t.s.client_fd, c->fd);
    ck_assert_ptr_eq(&t.s.origin_fd, o->fd);
    ck_assert_ptr_eq(c->rb, o->wb);
    ck_assert_ptr_eq(c->wb, o->rb);
    ck_assert_ptr_eq(o, c->other);
    ck_assert_ptr_eq(c, o->other);
    ck_assert_uint_eq(OP_READ | OP_WRITE, c->duplex);
    ck_assert_uint_eq(OP_READ | OP_WRITE, o->duplex);

    conn_close(&t);
}
END_TEST

START_TEST (test_start_pipelined_bytes_enable_origin_write) {
    // bytes que el cliente mandó pegados al REQUEST quedaron en read_buffer:
    // el origen debe arrancar con OP_WRITE además de OP_READ.
    struct test_conn t;
    conn_init(&t);
    buffer_preload(&t.s.read_buffer, (const uint8_t *)"early", 5);
    struct selector_key key = key_for(&t, t.s.client_fd);

    reset_injection();
    unsigned st = copy_start(&key);

    ck_assert_uint_eq(COPY, st);
    ck_assert_uint_eq(OP_READ,            g_interest[t.s.client_fd]);
    ck_assert_uint_eq(OP_READ | OP_WRITE, g_interest[t.s.origin_fd]);

    conn_close(&t);
}
END_TEST

START_TEST (test_start_setinterest_failure_returns_error) {
    // el selector puede fallar en cualquiera de los dos set_interest iniciales.
    struct test_conn t;
    struct selector_key key;

    for(int fail_at = 1; fail_at <= 2; fail_at++) {
        conn_init(&t);
        key = key_for(&t, t.s.client_fd);

        reset_injection();
        g_setinterest_fail_from = fail_at;
        unsigned st = copy_start(&key);

        ck_assert_uint_eq(ERROR, st);
        conn_close(&t);
    }
}
END_TEST

//////////////////////////////////////////////////////////////////////
// relay: los bytes cruzan en ambos sentidos

START_TEST (test_relay_client_to_origin) {
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    // el cliente manda bytes → copy_r los deposita en read_buffer
    ck_assert_int_eq(5, write(t.client_peer, "hola!", 5));
    struct selector_key rkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_r(&rkey));
    ck_assert(buffer_can_read(&t.s.read_buffer));
    // con datos cliente→origen pendientes, el origen queda con OP_WRITE
    ck_assert_uint_eq(OP_READ | OP_WRITE, g_interest[t.s.origin_fd]);

    // el origen queda escribible → copy_w drena hacia el origin_fd
    struct selector_key wkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(COPY, copy_w(&wkey));
    char got[16];
    ck_assert_int_eq(5, read(t.origin_peer, got, sizeof(got)));
    ck_assert_int_eq(0, memcmp("hola!", got, 5));
    // drenado: el origen vuelve a interesarse solo por lectura
    ck_assert_uint_eq(OP_READ, g_interest[t.s.origin_fd]);

    conn_close(&t);
}
END_TEST

START_TEST (test_relay_origin_to_client) {
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    ck_assert_int_eq(9, write(t.origin_peer, "respuesta", 9));
    struct selector_key rkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(COPY, copy_r(&rkey));
    ck_assert_uint_eq(OP_READ | OP_WRITE, g_interest[t.s.client_fd]);

    struct selector_key wkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_w(&wkey));
    char got[16];
    ck_assert_int_eq(9, read(t.client_peer, got, sizeof(got)));
    ck_assert_int_eq(0, memcmp("respuesta", got, 9));

    conn_close(&t);
}
END_TEST

START_TEST (test_pipelined_bytes_flow_without_recv) {
    // lo que quedó en read_buffer tras el REQUEST sale hacia el origen en el
    // primer copy_w, sin que haya habido ningún recv del cliente.
    struct test_conn t;
    conn_init(&t);
    buffer_preload(&t.s.read_buffer, (const uint8_t *)"early", 5);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    struct selector_key wkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(COPY, copy_w(&wkey));

    ck_assert_int_eq(0, g_recv_calls);
    char got[16];
    ck_assert_int_eq(5, read(t.origin_peer, got, sizeof(got)));
    ck_assert_int_eq(0, memcmp("early", got, 5));

    conn_close(&t);
}
END_TEST

//////////////////////////////////////////////////////////////////////
// backpressure y guardas defensivas

START_TEST (test_backpressure_full_buffer_drops_read) {
    // read_buffer (cliente→origen) lleno: el cliente no debe interesarse por
    // leer hasta que el origen drene.
    struct test_conn t;
    conn_init(&t);
    // llenar read_buffer por completo
    size_t space;
    memset(buffer_write_ptr(&t.s.read_buffer, &space), 'x', space);
    buffer_write_adv(&t.s.read_buffer, space);

    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    // cliente: sin lugar donde depositar (rb lleno) y sin nada para mandarle
    // (wb vacío) ⇒ OP_NOOP. Origen: lugar para leer + datos para escribir.
    ck_assert_uint_eq(OP_NOOP,            g_interest[t.s.client_fd]);
    ck_assert_uint_eq(OP_READ | OP_WRITE, g_interest[t.s.origin_fd]);

    // el origen drena una tanda → el cliente recupera OP_READ
    struct selector_key wkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(COPY, copy_w(&wkey));
    ck_assert_uint_eq(OP_READ, g_interest[t.s.client_fd]);

    conn_close(&t);
}
END_TEST

START_TEST (test_copy_r_full_buffer_does_not_recv) {
    // evento espurio de lectura con el buffer destino lleno: no se llama a
    // recv (recv de 0 bytes devolvería 0 = falso EOF); se recomputa y sigue.
    struct test_conn t;
    conn_init(&t);
    size_t space;
    memset(buffer_write_ptr(&t.s.read_buffer, &space), 'x', space);
    buffer_write_adv(&t.s.read_buffer, space);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    struct selector_key rkey = key_for(&t, t.s.client_fd);
    unsigned st = copy_r(&rkey);

    ck_assert_uint_eq(COPY, st);
    ck_assert_int_eq(0, g_recv_calls);
    ck_assert_uint_eq(OP_NOOP, g_interest[t.s.client_fd]);   // recomputado

    conn_close(&t);
}
END_TEST

START_TEST (test_copy_w_empty_buffer_does_not_send) {
    // evento espurio de escritura con el buffer fuente vacío: no se llama a
    // send; se recomputa y sigue.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    struct selector_key wkey = key_for(&t, t.s.origin_fd);
    unsigned st = copy_w(&wkey);

    ck_assert_uint_eq(COPY, st);
    ck_assert_int_eq(0, g_send_calls);
    ck_assert_uint_eq(OP_READ, g_interest[t.s.origin_fd]);

    conn_close(&t);
}
END_TEST

//////////////////////////////////////////////////////////////////////
// taxonomía de errno y EOF

START_TEST (test_nonfatal_recv_errnos_stay_in_copy) {
    const int errnos[] = { EAGAIN, EWOULDBLOCK, EINTR };
    struct test_conn t;

    for(unsigned i = 0; i < N(errnos); i++) {
        conn_init(&t);
        struct selector_key key = key_for(&t, t.s.client_fd);
        reset_injection();
        ck_assert_uint_eq(COPY, copy_start(&key));

        g_recv_inject_errno = errnos[i];
        struct selector_key rkey = key_for(&t, t.s.client_fd);
        unsigned st = copy_r(&rkey);

        ck_assert_uint_eq(COPY, st);
        ck_assert(!buffer_can_read(&t.s.read_buffer));   // nada avanzó
        conn_close(&t);
    }
}
END_TEST

START_TEST (test_nonfatal_send_errnos_stay_in_copy) {
    const int errnos[] = { EAGAIN, EWOULDBLOCK, EINTR };
    struct test_conn t;

    for(unsigned i = 0; i < N(errnos); i++) {
        conn_init(&t);
        buffer_preload(&t.s.read_buffer, (const uint8_t *)"data", 4);
        struct selector_key key = key_for(&t, t.s.client_fd);
        reset_injection();
        ck_assert_uint_eq(COPY, copy_start(&key));

        g_send_inject_errno = errnos[i];
        struct selector_key wkey = key_for(&t, t.s.origin_fd);
        unsigned st = copy_w(&wkey);

        ck_assert_uint_eq(COPY, st);
        ck_assert(buffer_can_read(&t.s.read_buffer));   // los datos siguen ahí
        conn_close(&t);
    }
}
END_TEST

START_TEST (test_fatal_errno_returns_error) {
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    g_recv_inject_errno = ECONNRESET;
    struct selector_key rkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(ERROR, copy_r(&rkey));

    // simétrico para send
    g_recv_inject_errno = 0;
    buffer_preload(&t.s.read_buffer, (const uint8_t *)"data", 4);
    g_send_inject_errno = EPIPE;
    struct selector_key wkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(ERROR, copy_w(&wkey));

    conn_close(&t);
}
END_TEST

//////////////////////////////////////////////////////////////////////
// half-close: un sentido sobrevive al otro, FIN diferido e idempotente

START_TEST (test_half_close_keeps_other_direction_alive) {
    // el cliente cierra su escritura pero el origen sigue mandando: el estado
    // sigue en COPY, el FIN se propaga al origen (sin bytes en vuelo) y la
    // respuesta del origen sigue llegando al cliente.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    ck_assert_int_eq(0, shutdown(t.client_peer, SHUT_WR));
    g_shutdown_wr_calls = 0;   // descontar el shutdown del propio test
    struct selector_key rkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_r(&rkey));

    // el FIN llegó al peer del origen (EOF inmediato, no había bytes en vuelo)
    ck_assert_int_eq(1, g_shutdown_wr_calls);
    char got[16];
    ck_assert_int_eq(0, read(t.origin_peer, got, sizeof(got)));

    // el sentido origen→cliente sigue vivo
    ck_assert_int_eq(4, write(t.origin_peer, "pong", 4));
    struct selector_key orkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(COPY, copy_r(&orkey));
    struct selector_key cwkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_w(&cwkey));
    ck_assert_int_eq(4, read(t.client_peer, got, sizeof(got)));
    ck_assert_int_eq(0, memcmp("pong", got, 4));

    conn_close(&t);
}
END_TEST

START_TEST (test_deferred_shutdown_flushes_in_flight_bytes) {
    // EOF del cliente con bytes todavía en read_buffer: el origen tiene que
    // recibir esos bytes ANTES del FIN (shutdown diferido al drenar).
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    ck_assert_int_eq(4, write(t.client_peer, "tail", 4));
    ck_assert_int_eq(0, shutdown(t.client_peer, SHUT_WR));
    g_shutdown_wr_calls = 0;

    struct selector_key rkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_r(&rkey));   // lee "tail"
    ck_assert_uint_eq(COPY, copy_r(&rkey));   // ve el EOF
    // hay bytes en vuelo: el FIN quedó pendiente
    ck_assert_int_eq(0, g_shutdown_wr_calls);

    // el drenado hacia el origen dispara el FIN diferido
    struct selector_key wkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(COPY, copy_w(&wkey));
    ck_assert_int_eq(1, g_shutdown_wr_calls);

    // el peer del origen ve los datos completos y recién después el EOF
    char got[16];
    ck_assert_int_eq(4, read(t.origin_peer, got, sizeof(got)));
    ck_assert_int_eq(0, memcmp("tail", got, 4));
    ck_assert_int_eq(0, read(t.origin_peer, got, sizeof(got)));

    conn_close(&t);
}
END_TEST

START_TEST (test_shutdown_wr_emitted_at_most_once) {
    // un segundo evento de EOF (espurio) no debe repetir el shutdown(SHUT_WR):
    // el bit de duplex hace de guarda.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    ck_assert_int_eq(0, shutdown(t.client_peer, SHUT_WR));
    g_shutdown_wr_calls = 0;
    struct selector_key rkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_r(&rkey));
    ck_assert_uint_eq(COPY, copy_r(&rkey));   // EOF espurio repetido

    ck_assert_int_eq(1, g_shutdown_wr_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_shutdown_wr_failure_returns_error) {
    // sin FIN el peer nunca ve fin de stream: un fallo real de SHUT_WR es
    // teardown explícito.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    ck_assert_int_eq(0, shutdown(t.client_peer, SHUT_WR));
    g_shutdown_wr_fail = true;
    struct selector_key rkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(ERROR, copy_r(&rkey));

    conn_close(&t);
}
END_TEST

START_TEST (test_shutdown_rd_failure_is_ignored) {
    // SHUT_RD es best-effort: su fallo no tira la conexión.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    ck_assert_int_eq(0, shutdown(t.client_peer, SHUT_WR));
    g_shutdown_rd_fail = true;
    struct selector_key rkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_r(&rkey));

    conn_close(&t);
}
END_TEST

START_TEST (test_both_eof_with_drained_buffers_returns_done) {
    // fin total: EOF de ambos lados con buffers vacíos ⇒ DONE, con un FIN
    // propagado a cada fd (duplex de ambos lados en OP_NOOP).
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    ck_assert_int_eq(0, shutdown(t.client_peer, SHUT_WR));
    ck_assert_int_eq(0, shutdown(t.origin_peer, SHUT_WR));
    g_shutdown_wr_calls = 0;

    struct selector_key crkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_r(&crkey));   // primer EOF: half-close
    struct selector_key orkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(DONE, copy_r(&orkey));   // segundo EOF: fin total

    ck_assert_int_eq(2, g_shutdown_wr_calls);  // un FIN por fd
    ck_assert_uint_eq(OP_NOOP, t.s.client.copy.duplex);
    ck_assert_uint_eq(OP_NOOP, t.s.orig.copy.duplex);

    conn_close(&t);
}
END_TEST

//////////////////////////////////////////////////////////////////////
// métricas: una sola vez por byte

START_TEST (test_metrics_count_relayed_bytes_once) {
    // N bytes ida + M bytes vuelta suman N+M exacto: se cuentan en el recv;
    // si el send también contara, daría el doble.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    const uint64_t base = metrics_get_total_bytes_transferred();

    // 5 bytes cliente→origen, con su send incluido
    ck_assert_int_eq(5, write(t.client_peer, "cinco", 5));
    struct selector_key crkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_r(&crkey));
    struct selector_key owkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(COPY, copy_w(&owkey));

    // 9 bytes origen→cliente, con su send incluido
    ck_assert_int_eq(9, write(t.origin_peer, "respuesta", 9));
    struct selector_key orkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(COPY, copy_r(&orkey));
    struct selector_key cwkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_w(&cwkey));

    ck_assert_uint_eq(base + 5 + 9, metrics_get_total_bytes_transferred());

    conn_close(&t);
}
END_TEST

START_TEST (test_metrics_not_counted_on_failed_recv) {
    // un recv fallido (errno inyectado) o un EOF no suman bytes.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    const uint64_t base = metrics_get_total_bytes_transferred();

    g_recv_inject_errno = EAGAIN;
    struct selector_key rkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_r(&rkey));

    g_recv_inject_errno = 0;
    ck_assert_int_eq(0, shutdown(t.client_peer, SHUT_WR));
    ck_assert_uint_eq(COPY, copy_r(&rkey));   // EOF

    ck_assert_uint_eq(base, metrics_get_total_bytes_transferred());

    conn_close(&t);
}
END_TEST

START_TEST (test_full_half_close_lifecycle) {
    // ciclo completo estilo HTTP/1.0: el cliente manda el pedido y cierra su
    // escritura; el proxy entrega pedido+FIN al origen; el origen responde y
    // cierra; el cliente recibe la respuesta completa y la conexión termina.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    // cliente: pedido + half-close
    ck_assert_int_eq(3, write(t.client_peer, "GET", 3));
    ck_assert_int_eq(0, shutdown(t.client_peer, SHUT_WR));
    struct selector_key crkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(COPY, copy_r(&crkey));   // lee "GET"
    ck_assert_uint_eq(COPY, copy_r(&crkey));   // EOF (FIN diferido: hay bytes)

    // el origen recibe pedido + FIN
    struct selector_key owkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(COPY, copy_w(&owkey));
    char got[16];
    ck_assert_int_eq(3, read(t.origin_peer, got, sizeof(got)));
    ck_assert_int_eq(0, memcmp("GET", got, 3));
    ck_assert_int_eq(0, read(t.origin_peer, got, sizeof(got)));

    // el origen responde y cierra
    ck_assert_int_eq(2, write(t.origin_peer, "OK", 2));
    ck_assert_int_eq(0, shutdown(t.origin_peer, SHUT_WR));
    struct selector_key orkey = key_for(&t, t.s.origin_fd);
    ck_assert_uint_eq(COPY, copy_r(&orkey));   // lee "OK"
    ck_assert_uint_eq(COPY, copy_r(&orkey));   // EOF (FIN diferido: hay bytes)

    // el cliente recibe la respuesta completa; drenar cierra todo
    struct selector_key cwkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(DONE, copy_w(&cwkey));
    ck_assert_int_eq(2, read(t.client_peer, got, sizeof(got)));
    ck_assert_int_eq(0, memcmp("OK", got, 2));
    ck_assert_int_eq(0, read(t.client_peer, got, sizeof(got)));

    conn_close(&t);
}
END_TEST

START_TEST (test_recompute_failure_after_io_returns_error) {
    // el I/O sale bien pero el recomputo de intereses falla ⇒ ERROR (ambos
    // set_interest deben tener éxito).
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    ck_assert_int_eq(4, write(t.client_peer, "data", 4));
    g_setinterest_fail_from = g_setinterest_calls + 2;   // falla el 2º recomputo
    struct selector_key rkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(ERROR, copy_r(&rkey));

    conn_close(&t);
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("state_copy");
    TCase *tc = tcase_create("copy");

    tcase_add_test(tc, test_start_wires_and_sets_initial_interests);
    tcase_add_test(tc, test_start_pipelined_bytes_enable_origin_write);
    tcase_add_test(tc, test_start_setinterest_failure_returns_error);
    tcase_add_test(tc, test_relay_client_to_origin);
    tcase_add_test(tc, test_relay_origin_to_client);
    tcase_add_test(tc, test_pipelined_bytes_flow_without_recv);
    tcase_add_test(tc, test_backpressure_full_buffer_drops_read);
    tcase_add_test(tc, test_copy_r_full_buffer_does_not_recv);
    tcase_add_test(tc, test_copy_w_empty_buffer_does_not_send);
    tcase_add_test(tc, test_nonfatal_recv_errnos_stay_in_copy);
    tcase_add_test(tc, test_nonfatal_send_errnos_stay_in_copy);
    tcase_add_test(tc, test_fatal_errno_returns_error);
    tcase_add_test(tc, test_recompute_failure_after_io_returns_error);
    tcase_add_test(tc, test_half_close_keeps_other_direction_alive);
    tcase_add_test(tc, test_deferred_shutdown_flushes_in_flight_bytes);
    tcase_add_test(tc, test_shutdown_wr_emitted_at_most_once);
    tcase_add_test(tc, test_shutdown_wr_failure_returns_error);
    tcase_add_test(tc, test_shutdown_rd_failure_is_ignored);
    tcase_add_test(tc, test_both_eof_with_drained_buffers_returns_done);
    tcase_add_test(tc, test_metrics_count_relayed_bytes_once);
    tcase_add_test(tc, test_metrics_not_counted_on_failed_recv);
    tcase_add_test(tc, test_full_half_close_lifecycle);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void) {
    SRunner *sr = srunner_create(suite());
    int number_failed;

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

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
// interceptan con --wrap para inyectar errno sin depender del kernel.
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

static void
reset_injection(void) {
    memset(g_interest, 0xFF, sizeof(g_interest));  // 0xFF = "nunca seteado"
    g_setinterest_calls     = 0;
    g_setinterest_fail_from = 0;
    g_recv_calls            = 0;
    g_recv_inject_errno     = 0;
    g_send_calls            = 0;
    g_send_inject_errno     = 0;
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

//////////////////////////////////////////////////////////////////////
// Harness: un `struct socks5' con socketpairs reales como cliente y origen.
// El lado "local" de cada par es el fd del proxy; el "peer" simula al cliente
// o al origin server remoto.

struct test_conn {
    struct socks5 s;
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

    buffer_init(&t->s.read_buffer,  N(t->s.raw_buff_a), t->s.raw_buff_a);
    buffer_init(&t->s.write_buffer, N(t->s.raw_buff_b), t->s.raw_buff_b);
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

START_TEST (test_eof_returns_done) {
    // política del paso 1: EOF de cualquier lado cierra la conexión completa.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = key_for(&t, t.s.client_fd);
    reset_injection();
    ck_assert_uint_eq(COPY, copy_start(&key));

    ck_assert_int_eq(0, shutdown(t.client_peer, SHUT_WR));
    struct selector_key rkey = key_for(&t, t.s.client_fd);
    ck_assert_uint_eq(DONE, copy_r(&rkey));

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
    tcase_add_test(tc, test_eof_returns_done);
    tcase_add_test(tc, test_recompute_failure_after_io_returns_error);
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

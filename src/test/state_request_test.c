#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <check.h>

// se incluye el .c para probar `request_write' (transiciones post-reply) sin
// linkear selector.c ni los módulos de connect/copy: sus símbolos se satisfacen
// con stubs propios (abajo). request_parser.c y buffer.c se linkean reales.
// send() se intercepta con --wrap para poder forzar un envío parcial.
#include "states/state_request.c"

//////////////////////////////////////////////////////////////////////
// Stubs de los símbolos externos que referencia state_request.c.

static int      g_connect_start_calls = 0;
static int      g_copy_start_calls    = 0;
static unsigned g_copy_start_ret      = COPY;
static size_t   g_send_limit          = 0;   // tope de bytes por send; 0 = sin tope

static void
reset_injection(void) {
    g_connect_start_calls = 0;
    g_copy_start_calls    = 0;
    g_copy_start_ret      = COPY;
    g_send_limit          = 0;
}

unsigned
connect_start(struct selector_key *key) {
    (void)key;
    g_connect_start_calls++;
    return CONNECTING;
}

unsigned
copy_start(struct selector_key *key) {
    (void)key;
    g_copy_start_calls++;
    return g_copy_start_ret;
}

selector_status
selector_set_interest_key(struct selector_key *key, fd_interest i) {
    (void)key; (void)i;
    return SELECTOR_SUCCESS;
}

extern ssize_t __real_send(int fd, const void *buf, size_t len, int flags);

ssize_t
__wrap_send(int fd, const void *buf, size_t len, int flags) {
    if(g_send_limit != 0 && len > g_send_limit) {
        len = g_send_limit;
    }
    return __real_send(fd, buf, len, flags);
}

//////////////////////////////////////////////////////////////////////
// Harness: un `struct socks5' con un socketpair real como cliente, y el REPLY
// ya serializado con el request_reply de verdad (deja `reply_rep' cargado).

struct test_conn {
    struct socks5 s;
    int           client_peer;
};

static void
conn_init(struct test_conn *t) {
    int c[2];
    ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, c));

    memset(&t->s, 0, sizeof(t->s));
    t->s.client_fd = c[0];
    t->client_peer = c[1];
    t->s.origin_fd = -1;
    ck_assert_int_ne(-1, fcntl(t->s.client_fd, F_SETFL, O_NONBLOCK));

    buffer_init(&t->s.read_buffer,  N(t->s.raw_buff_a), t->s.raw_buff_a);
    buffer_init(&t->s.write_buffer, N(t->s.raw_buff_b), t->s.raw_buff_b);
    t->s.client.request.rb = &t->s.read_buffer;
    t->s.client.request.wb = &t->s.write_buffer;
}

static void
conn_close(struct test_conn *t) {
    close(t->s.client_fd);
    close(t->client_peer);
}

/* deja el REPLY con el REP dado serializado en write_buffer, como en el server */
static void
reply_ready(struct test_conn *t, uint8_t rep) {
    ck_assert_int_gt(request_reply(&t->s, rep, SOCKS5_ATYP_IPV4,
                                   bnd_addr_none, 0), 0);
    ck_assert_uint_eq(rep, t->s.reply_rep);
}

//////////////////////////////////////////////////////////////////////

START_TEST (test_success_reply_starts_copy) {
    // REP de éxito + origen conectado ⇒ al drenar el reply arranca el relay.
    struct test_conn t;
    conn_init(&t);
    t.s.origin_fd = 42;   // origen "conectado" (no se hace I/O sobre él acá)
    reply_ready(&t, SOCKS5_REP_SUCCEEDED);
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    unsigned st = request_write(&key);

    ck_assert_uint_eq(COPY, st);
    ck_assert_int_eq(1, g_copy_start_calls);
    ck_assert(!buffer_can_read(&t.s.write_buffer));   // reply completo enviado

    conn_close(&t);
}
END_TEST

START_TEST (test_success_reply_without_origin_closes) {
    // defensivo: REP de éxito pero sin origen conectado ⇒ no hay relay posible.
    struct test_conn t;
    conn_init(&t);   // origin_fd = -1
    reply_ready(&t, SOCKS5_REP_SUCCEEDED);
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    unsigned st = request_write(&key);

    ck_assert_uint_eq(DONE, st);
    ck_assert_int_eq(0, g_copy_start_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_error_reply_closes) {
    // tras un reply de error se cierra la conexión (RFC 1928 §6), haya o no
    // un origen en juego.
    const uint8_t reps[] = {
        SOCKS5_REP_GENERAL_FAILURE,
        SOCKS5_REP_HOST_UNREACHABLE,
        SOCKS5_REP_CONN_REFUSED,
        SOCKS5_REP_CMD_NOT_SUPPORTED,
    };
    struct test_conn t;

    for(unsigned i = 0; i < N(reps); i++) {
        conn_init(&t);
        reply_ready(&t, reps[i]);
        struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

        reset_injection();
        unsigned st = request_write(&key);

        ck_assert_uint_eq(DONE, st);
        ck_assert_int_eq(0, g_copy_start_calls);
        conn_close(&t);
    }
}
END_TEST

START_TEST (test_partial_send_stays_in_request_write) {
    // el reply salió a medias: se sigue en REQUEST_WRITE sin arrancar el relay.
    struct test_conn t;
    conn_init(&t);
    t.s.origin_fd = 42;
    reply_ready(&t, SOCKS5_REP_SUCCEEDED);
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    g_send_limit = 3;   // el reply IPv4 mide 10 bytes: salen solo 3
    unsigned st = request_write(&key);

    ck_assert_uint_eq(REQUEST_WRITE, st);
    ck_assert_int_eq(0, g_copy_start_calls);
    ck_assert(buffer_can_read(&t.s.write_buffer));   // quedan bytes pendientes

    // sin el tope, el próximo evento drena y recién ahí arranca el relay
    g_send_limit = 0;
    st = request_write(&key);
    ck_assert_uint_eq(COPY, st);
    ck_assert_int_eq(1, g_copy_start_calls);

    conn_close(&t);
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("state_request");
    TCase *tc = tcase_create("request_write");

    tcase_add_test(tc, test_success_reply_starts_copy);
    tcase_add_test(tc, test_success_reply_without_origin_closes);
    tcase_add_test(tc, test_error_reply_closes);
    tcase_add_test(tc, test_partial_send_stays_in_request_write);
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

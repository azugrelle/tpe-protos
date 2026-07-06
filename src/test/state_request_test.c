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
    // respaldo de los buffers de I/O: en el server viven en el heap
    // (dimensionados por la config); el harness los provee embebidos
    uint8_t       buff_a[2048], buff_b[2048];
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

    t->s.raw_buff_a = t->buff_a;
    t->s.raw_buff_b = t->buff_b;
    t->s.buf_size   = sizeof(t->buff_a);
    buffer_init(&t->s.read_buffer,  t->s.buf_size, t->s.raw_buff_a);
    buffer_init(&t->s.write_buffer, t->s.buf_size, t->s.raw_buff_b);
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

/* deposita bytes en un buffer como si un recv previo los hubiera dejado */
static void
buf_fill(buffer *b, const uint8_t *data, size_t len) {
    size_t   space;
    uint8_t *ptr = buffer_write_ptr(b, &space);

    ck_assert_uint_ge(space, len);
    memcpy(ptr, data, len);
    buffer_write_adv(b, len);
}

/* CONNECT a 1.2.3.4:80, ATYP IPv4 (10 bytes) */
static const uint8_t connect_ipv4[] = {
    0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50,
};

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

START_TEST (test_start_without_pipelined_bytes_waits) {
    // read_buffer vacío: request_start solo deja el estado listo y espera
    // el evento de lectura.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    unsigned st = request_start(&key);

    ck_assert_uint_eq(REQUEST_READ, st);
    ck_assert_int_eq(0, g_connect_start_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_start_pipelined_request_processed_inline) {
    // el REQUEST completo ya estaba en el read_buffer (llegó pipelineado con
    // el hello/auth): por esos bytes no habrá evento de lectura, así que
    // request_start debe procesarlos inline y disparar la conexión al origen.
    struct test_conn t;
    conn_init(&t);
    buf_fill(&t.s.read_buffer, connect_ipv4, sizeof(connect_ipv4));
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    unsigned st = request_start(&key);

    ck_assert_uint_eq(CONNECTING, st);
    ck_assert_int_eq(1, g_connect_start_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_start_pipelined_partial_request_then_read_completes) {
    // solo un prefijo del REQUEST vino pipelineado: request_start lo consume
    // y queda en REQUEST_READ; el resto llega por el socket y request_read lo
    // completa sin perder lo ya parseado.
    struct test_conn t;
    conn_init(&t);
    buf_fill(&t.s.read_buffer, connect_ipv4, 4);   // hasta el ATYP inclusive
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    unsigned st = request_start(&key);
    ck_assert_uint_eq(REQUEST_READ, st);
    ck_assert_int_eq(0, g_connect_start_calls);

    const size_t rest = sizeof(connect_ipv4) - 4;
    ck_assert_int_eq((ssize_t)rest,
                     send(t.client_peer, connect_ipv4 + 4, rest, 0));
    st = request_read(&key);
    ck_assert_uint_eq(CONNECTING, st);
    ck_assert_int_eq(1, g_connect_start_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_start_pipelined_invalid_request_replies_error) {
    // el REQUEST pipelineado trae un CMD no soportado (BIND): el reply de
    // error queda serializado y se pasa a REQUEST_WRITE sin conectar.
    struct test_conn t;
    conn_init(&t);
    const uint8_t bind_req[] = {0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
    buf_fill(&t.s.read_buffer, bind_req, sizeof(bind_req));
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    unsigned st = request_start(&key);

    ck_assert_uint_eq(REQUEST_WRITE, st);
    ck_assert_int_eq(0, g_connect_start_calls);
    ck_assert_uint_eq(SOCKS5_REP_CMD_NOT_SUPPORTED, t.s.reply_rep);
    ck_assert(buffer_can_read(&t.s.write_buffer));   // reply listo para enviar

    conn_close(&t);
}
END_TEST

START_TEST (test_read_spurious_wakeup_keeps_reading) {
    // select puede reportar el fd legible y que el recv igual devuelva EAGAIN
    // (man 2 select, BUGS): no debe matar la conexión, solo seguir esperando.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    ck_assert_uint_eq(REQUEST_READ, request_start(&key));
    // socket no bloqueante sin datos pendientes: el recv da EAGAIN real
    unsigned st = request_read(&key);

    ck_assert_uint_eq(REQUEST_READ, st);
    ck_assert_int_eq(0, g_connect_start_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_read_eof_closes_cleanly) {
    // el cliente cierra antes de completar el REQUEST: es un cierre del peer
    // (DONE), no un error del server.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    ck_assert_uint_eq(REQUEST_READ, request_start(&key));
    shutdown(t.client_peer, SHUT_WR);   // el recv del server verá EOF
    unsigned st = request_read(&key);

    ck_assert_uint_eq(DONE, st);
    ck_assert_int_eq(0, g_connect_start_calls);

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

    TCase *tc_start = tcase_create("request_start");
    tcase_add_test(tc_start, test_start_without_pipelined_bytes_waits);
    tcase_add_test(tc_start, test_start_pipelined_request_processed_inline);
    tcase_add_test(tc_start, test_start_pipelined_partial_request_then_read_completes);
    tcase_add_test(tc_start, test_start_pipelined_invalid_request_replies_error);
    suite_add_tcase(s, tc_start);

    TCase *tc_read = tcase_create("request_read");
    tcase_add_test(tc_read, test_read_spurious_wakeup_keeps_reading);
    tcase_add_test(tc_read, test_read_eof_closes_cleanly);
    suite_add_tcase(s, tc_read);

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

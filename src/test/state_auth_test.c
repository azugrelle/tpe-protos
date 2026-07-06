#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <check.h>

// se incluye el .c para probar `auth_start'/`auth_read'/`auth_write' (el
// subnegotiation completo, incluidos bytes pipelineados con el hello) sin
// linkear selector.c ni user_auth_utils.c: sus símbolos se satisfacen con
// stubs propios (abajo). auth_parser.c y buffer.c se linkean reales.
#include "states/state_auth.c"

//////////////////////////////////////////////////////////////////////
// Stubs de los símbolos externos que referencia state_auth.c.

static int     g_request_start_calls = 0;
static int     g_credentials_calls   = 0;
static uint8_t g_credentials_result  = 0x00;   // SOCKS_AUTH_STATUS_SUCCESS
static char    g_seen_username[SOCKS_AUTH_MAX_LEN];
static char    g_seen_password[SOCKS_AUTH_MAX_LEN];
static int     g_add_user_calls      = 0;
static char    g_added_username[SOCKS_AUTH_MAX_LEN];

static void
reset_injection(void) {
    g_request_start_calls = 0;
    g_credentials_calls   = 0;
    g_credentials_result  = SOCKS_AUTH_STATUS_SUCCESS;
    g_seen_username[0]    = '\0';
    g_seen_password[0]    = '\0';
    g_add_user_calls      = 0;
    g_added_username[0]   = '\0';
}

unsigned
request_start(struct selector_key *key) {
    (void)key;
    g_request_start_calls++;
    return REQUEST_READ;
}

uint8_t
check_if_valid_credentials(const char *username, const char *password) {
    g_credentials_calls++;
    snprintf(g_seen_username, sizeof(g_seen_username), "%s", username);
    snprintf(g_seen_password, sizeof(g_seen_password), "%s", password);
    return g_credentials_result;
}

selector_status
selector_set_interest_key(struct selector_key *key, fd_interest i) {
    (void)key; (void)i;
    return SELECTOR_SUCCESS;
}

void
metrics_add_user(const char *username) {
    g_add_user_calls++;
    snprintf(g_added_username, sizeof(g_added_username), "%s", username);
}

//////////////////////////////////////////////////////////////////////
// Harness: un `struct socks5' con un socketpair real como cliente.

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
}

static void
conn_close(struct test_conn *t) {
    close(t->s.client_fd);
    close(t->client_peer);
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

/* subnegotiation VER=1, "user"/"pass" (RFC 1929 §2, 11 bytes) */
static const uint8_t auth_user_pass[] = {
    0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's',
};

//////////////////////////////////////////////////////////////////////

START_TEST (test_start_without_pipelined_bytes_waits) {
    // read_buffer vacío: auth_start solo deja el estado listo y espera el
    // evento de lectura.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    unsigned st = auth_start(&key);

    ck_assert_uint_eq(AUTH_READ, st);
    ck_assert_int_eq(0, g_credentials_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_start_pipelined_auth_processed_inline) {
    // el subnegotiation completo ya estaba en el read_buffer (llegó
    // pipelineado con el hello): por esos bytes no habrá evento de lectura,
    // así que auth_start debe procesarlos inline y dejar la respuesta lista.
    struct test_conn t;
    conn_init(&t);
    buf_fill(&t.s.read_buffer, auth_user_pass, sizeof(auth_user_pass));
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    unsigned st = auth_start(&key);

    ck_assert_uint_eq(AUTH_WRITE, st);
    ck_assert_int_eq(1, g_credentials_calls);
    ck_assert_str_eq("user", g_seen_username);
    ck_assert_str_eq("pass", g_seen_password);
    ck_assert_str_eq("user", t.s.username);
    // credenciales válidas: el usuario queda registrado como activo
    ck_assert_int_eq(1, g_add_user_calls);
    ck_assert_str_eq("user", g_added_username);
    ck_assert(buffer_can_read(&t.s.write_buffer));   // respuesta serializada

    conn_close(&t);
}
END_TEST

START_TEST (test_start_pipelined_partial_auth_then_read_completes) {
    // solo un prefijo del subnegotiation vino pipelineado: auth_start lo
    // consume y queda en AUTH_READ; el resto llega por el socket y auth_read
    // lo completa sin perder lo ya parseado.
    struct test_conn t;
    conn_init(&t);
    buf_fill(&t.s.read_buffer, auth_user_pass, 4);   // VER, ULEN y "us"
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    unsigned st = auth_start(&key);
    ck_assert_uint_eq(AUTH_READ, st);
    ck_assert_int_eq(0, g_credentials_calls);

    const size_t rest = sizeof(auth_user_pass) - 4;
    ck_assert_int_eq((ssize_t)rest,
                     send(t.client_peer, auth_user_pass + 4, rest, 0));
    st = auth_read(&key);
    ck_assert_uint_eq(AUTH_WRITE, st);
    ck_assert_int_eq(1, g_credentials_calls);
    ck_assert_str_eq("user", g_seen_username);
    ck_assert_str_eq("pass", g_seen_password);

    conn_close(&t);
}
END_TEST

START_TEST (test_start_pipelined_bad_version_errors) {
    // el subnegotiation pipelineado trae un VER inválido: se corta con ERROR
    // sin consultar credenciales.
    struct test_conn t;
    conn_init(&t);
    const uint8_t bad_ver[] = {0x05, 0x04, 'u', 's', 'e', 'r'};
    buf_fill(&t.s.read_buffer, bad_ver, sizeof(bad_ver));
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    unsigned st = auth_start(&key);

    ck_assert_uint_eq(ERROR, st);
    ck_assert_int_eq(0, g_credentials_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_start_rejects_embedded_nul_in_username) {
    struct test_conn t;
    conn_init(&t);
    const uint8_t auth[] = {
        0x01, 0x08, 'u', 's', 'e', 'r', 0x00, 'e', 'v', 'i',
        0x04, 'p', 'a', 's', 's',
    };
    buf_fill(&t.s.read_buffer, auth, sizeof(auth));
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    ck_assert_uint_eq(ERROR, auth_start(&key));
    ck_assert_int_eq(0, g_credentials_calls);
    ck_assert_int_eq(0, g_add_user_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_start_rejects_embedded_nul_in_password) {
    struct test_conn t;
    conn_init(&t);
    const uint8_t auth[] = {
        0x01, 0x04, 'u', 's', 'e', 'r',
        0x08, 'p', 'a', 's', 's', 0x00, 'e', 'v', 'i',
    };
    buf_fill(&t.s.read_buffer, auth, sizeof(auth));
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    ck_assert_uint_eq(ERROR, auth_start(&key));
    ck_assert_int_eq(0, g_credentials_calls);
    ck_assert_int_eq(0, g_add_user_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_start_pipelined_bad_credentials_still_replies) {
    // credenciales inválidas pipelineadas: igual se pasa a AUTH_WRITE con
    // STATUS de falla (la respuesta se envía antes de cerrar, RFC 1929 §2).
    struct test_conn t;
    conn_init(&t);
    buf_fill(&t.s.read_buffer, auth_user_pass, sizeof(auth_user_pass));
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    g_credentials_result = SOCKS_AUTH_STATUS_FAILURE;
    unsigned st = auth_start(&key);

    ck_assert_uint_eq(AUTH_WRITE, st);
    ck_assert_uint_eq(SOCKS_AUTH_STATUS_FAILURE, t.s.client.auth.status);
    // credenciales inválidas: nunca se registra como usuario activo
    ck_assert_int_eq(0, g_add_user_calls);

    // al drenar la respuesta de falla se cierra sin iniciar el REQUEST
    st = auth_write(&key);
    ck_assert_uint_eq(DONE, st);
    ck_assert_int_eq(0, g_request_start_calls);

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
    ck_assert_uint_eq(AUTH_READ, auth_start(&key));
    // socket no bloqueante sin datos pendientes: el recv da EAGAIN real
    unsigned st = auth_read(&key);

    ck_assert_uint_eq(AUTH_READ, st);
    ck_assert_int_eq(0, g_credentials_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_read_eof_closes_cleanly) {
    // el cliente cierra antes de completar el subnegotiation: es un cierre
    // del peer (DONE), no un error del server.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    ck_assert_uint_eq(AUTH_READ, auth_start(&key));
    shutdown(t.client_peer, SHUT_WR);   // el recv del server verá EOF
    unsigned st = auth_read(&key);

    ck_assert_uint_eq(DONE, st);
    ck_assert_int_eq(0, g_credentials_calls);

    conn_close(&t);
}
END_TEST

START_TEST (test_write_success_hands_off_to_request_start) {
    // respuesta de éxito drenada: auth_write delega en request_start, que es
    // quien procesa un REQUEST pipelineado si ya está en el read_buffer.
    struct test_conn t;
    conn_init(&t);
    struct selector_key key = { .s = NULL, .fd = t.s.client_fd, .data = &t.s };

    reset_injection();
    struct auth_st *d = &t.s.client.auth;
    d->rb     = &t.s.read_buffer;
    d->wb     = &t.s.write_buffer;
    d->status = SOCKS_AUTH_STATUS_SUCCESS;
    ck_assert_int_eq(2, auth_marshall(d->wb, d->status));

    unsigned st = auth_write(&key);

    ck_assert_uint_eq(REQUEST_READ, st);
    ck_assert_int_eq(1, g_request_start_calls);
    ck_assert(!buffer_can_read(&t.s.write_buffer));   // respuesta enviada

    conn_close(&t);
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("state_auth");
    TCase *tc = tcase_create("auth_start");

    tcase_add_test(tc, test_start_without_pipelined_bytes_waits);
    tcase_add_test(tc, test_start_pipelined_auth_processed_inline);
    tcase_add_test(tc, test_start_pipelined_partial_auth_then_read_completes);
    tcase_add_test(tc, test_start_pipelined_bad_version_errors);
    tcase_add_test(tc, test_start_rejects_embedded_nul_in_username);
    tcase_add_test(tc, test_start_rejects_embedded_nul_in_password);
    tcase_add_test(tc, test_start_pipelined_bad_credentials_still_replies);
    suite_add_tcase(s, tc);

    TCase *tc_read = tcase_create("auth_read");
    tcase_add_test(tc_read, test_read_spurious_wakeup_keeps_reading);
    tcase_add_test(tc_read, test_read_eof_closes_cleanly);
    suite_add_tcase(s, tc_read);

    TCase *tc_write = tcase_create("auth_write");
    tcase_add_test(tc_write, test_write_success_hands_off_to_request_start);
    suite_add_tcase(s, tc_write);

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

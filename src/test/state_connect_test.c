#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <check.h>

// se incluye el .c para poder probar sus funciones estáticas (connect_resolve)
// sin linkear selector.c ni state_request.c: los símbolos externos que referencia
// el módulo se satisfacen con stubs propios (abajo).
#include "states/state_connect.c"

//////////////////////////////////////////////////////////////////////
// Stubs de los símbolos externos que referencia state_connect.c, gobernados por
// globals para inyectar fallos. `reset_injection' los deja en su valor neutro.

static int     g_register_calls    = 0;  // intentos de selector_register
static bool    g_register_fail     = false;
static bool    g_setinterest_fail  = false;
static int     g_reply_calls       = 0;  // llamadas a request_reply
static uint8_t g_reply_rep         = 0;  // último REP serializado
static bool    g_inject            = false;  // habilita el script de connect()
static int     g_connect_calls     = 0;
static int     g_connect_fail_until = 0;  // connect() falla mientras call <= este

static void
reset_injection(void) {
    g_register_calls     = 0;
    g_register_fail      = false;
    g_setinterest_fail   = false;
    g_reply_calls        = 0;
    g_reply_rep          = 0;
    g_inject             = false;
    g_connect_calls      = 0;
    g_connect_fail_until = 0;
}

int
request_reply(struct socks5 *s, uint8_t rep, uint8_t bnd_atyp,
              const uint8_t *bnd_addr, uint16_t bnd_port) {
    (void)s; (void)bnd_atyp; (void)bnd_addr; (void)bnd_port;
    g_reply_calls++;
    g_reply_rep = rep;
    return 0;
}

selector_status
selector_set_interest(fd_selector s, int fd, fd_interest i) {
    (void)s; (void)fd; (void)i;
    return g_setinterest_fail ? SELECTOR_IO : SELECTOR_SUCCESS;
}

selector_status
selector_register(fd_selector s, const int fd, const fd_handler *handler,
                  const fd_interest interest, void *data) {
    (void)s; (void)fd; (void)handler; (void)interest; (void)data;
    g_register_calls++;
    return g_register_fail ? SELECTOR_MAXFD : SELECTOR_SUCCESS;
}

// connect() se intercepta con --wrap: por defecto delega en el real; cuando el
// test enciende g_inject, falla (ECONNREFUSED) mientras el nº de llamada sea
// <= g_connect_fail_until, y a partir de ahí devuelve éxito inmediato.
extern int __real_connect(int fd, const struct sockaddr *addr, socklen_t len);

int
__wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if(!g_inject) {
        return __real_connect(fd, addr, len);
    }
    g_connect_calls++;
    if(g_connect_calls <= g_connect_fail_until) {
        errno = ECONNREFUSED;
        return -1;
    }
    return 0;
}

selector_status
selector_unregister_fd(fd_selector s, const int fd) {
    (void)s; (void)fd;
    return SELECTOR_SUCCESS;
}

int
selector_fd_set_nio(const int fd) {
    (void)fd;
    return 0;
}

const fd_handler *
socks5_handler_ref(void) {
    return NULL;
}

/* arma un `struct socks5' mínimo con el destino ya "parseado" */
static void
init_dest(struct socks5 *s, uint8_t atyp, const char *host, uint16_t port) {
    memset(s, 0, sizeof(*s));
    s->dest_atyp = atyp;
    s->dest_port = port;
    strcpy(s->dest_host, host);
}

START_TEST (test_resolve_ipv4_literal) {
    struct socks5 s;
    init_dest(&s, SOCKS5_ATYP_IPV4, "127.0.0.1", 8080);

    int gai = connect_resolve(&s);

    ck_assert_int_eq(0, gai);
    ck_assert_ptr_nonnull(s.origin_resolution);
    // el cursor arranca apuntando a la cabeza de la lista
    ck_assert_ptr_eq(s.origin_resolution, s.origin_resolution_current);

    struct addrinfo *ai = s.origin_resolution;
    // los hints se reflejan en el resultado
    ck_assert_int_eq(AF_INET,     ai->ai_family);
    ck_assert_int_eq(SOCK_STREAM, ai->ai_socktype);
    ck_assert_int_eq(IPPROTO_TCP, ai->ai_protocol);

    // el sockaddr quedó listo para connect: 127.0.0.1:8080
    struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
    ck_assert_int_eq(AF_INET, sin->sin_family);
    ck_assert_uint_eq(htons(8080), sin->sin_port);
    ck_assert_uint_eq(inet_addr("127.0.0.1"), sin->sin_addr.s_addr);

    freeaddrinfo(s.origin_resolution);
}
END_TEST

START_TEST (test_resolve_numerichost_rejects_fqdn) {
    // ATYP IPv4 ⇒ AI_NUMERICHOST: un FQDN no numérico debe fallar SIN tocar la
    // red (prueba hermética de que el flag quedó puesto). No hay lookup DNS.
    struct socks5 s;
    init_dest(&s, SOCKS5_ATYP_IPV4, "example.com", 80);

    int gai = connect_resolve(&s);

    ck_assert_int_ne(0, gai);
    ck_assert_ptr_null(s.origin_resolution);
    ck_assert_ptr_null(s.origin_resolution_current);
}
END_TEST

START_TEST (test_bnd_from_bound_socket) {
    // getsockname sobre un socket con dirección local conocida devuelve ese BND.
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port        = 0;   // puerto efímero
    ck_assert_int_eq(0, bind(fd, (struct sockaddr *)&a, sizeof(a)));
    struct sockaddr_in got;
    socklen_t gl = sizeof(got);
    ck_assert_int_eq(0, getsockname(fd, (struct sockaddr *)&got, &gl));

    uint8_t  atyp;
    uint8_t  addr[4];
    uint16_t port;
    connect_reply_bnd(fd, &atyp, addr, &port);

    ck_assert_uint_eq(SOCKS5_ATYP_IPV4, atyp);
    uint8_t expect[4] = {127, 0, 0, 1};
    ck_assert_int_eq(0, memcmp(addr, expect, 4));
    ck_assert_uint_eq(ntohs(got.sin_port), port);
    close(fd);
}
END_TEST

START_TEST (test_bnd_degrades_on_bad_fd) {
    // getsockname sobre un fd inválido falla ⇒ BND degradado a 0.0.0.0:0.
    uint8_t  atyp = 0xFF;
    uint8_t  addr[4] = {9, 9, 9, 9};
    uint16_t port = 1234;
    connect_reply_bnd(-1, &atyp, addr, &port);

    ck_assert_uint_eq(SOCKS5_ATYP_IPV4, atyp);
    uint8_t zero[4] = {0, 0, 0, 0};
    ck_assert_int_eq(0, memcmp(addr, zero, 4));
    ck_assert_uint_eq(0, port);
}
END_TEST

/* nodo de addrinfo con su sockaddr_in para armar una lista a mano */
static void
init_ai(struct addrinfo *ai, struct sockaddr_in *sin, const char *ip,
        uint16_t port, struct addrinfo *next) {
    memset(sin, 0, sizeof(*sin));
    sin->sin_family      = AF_INET;
    sin->sin_addr.s_addr = inet_addr(ip);
    sin->sin_port        = htons(port);
    memset(ai, 0, sizeof(*ai));
    ai->ai_family   = AF_INET;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addr     = (struct sockaddr *)sin;
    ai->ai_addrlen  = sizeof(*sin);
    ai->ai_next     = next;
}

START_TEST (test_connect_retry_second_candidate) {
    // dos candidatos: el 1º rechaza (connect inmediato falla), el 2º conecta.
    struct sockaddr_in a0, a1;
    struct addrinfo    n0, n1;
    init_ai(&n1, &a1, "127.0.0.2", 2222, NULL);
    init_ai(&n0, &a0, "127.0.0.1", 1111, &n1);

    struct socks5 s;
    memset(&s, 0, sizeof(s));
    s.client_fd                 = 100;
    s.origin_fd                 = -1;
    s.references                = 1;
    s.origin_resolution         = &n0;   // a mano: no se libera (no es getaddrinfo)
    s.origin_resolution_current = &n0;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    g_inject = true; g_connect_fail_until = 1;   // 1er candidato falla, 2º conecta
    unsigned st = connect_try(&key);

    ck_assert_uint_eq(CONNECTING, st);
    ck_assert_uint_eq(2, s.references);                  // client_fd + origin_fd
    ck_assert_int_eq(1, g_register_calls);               // origin registrado una vez
    ck_assert_ptr_eq(&n1, s.origin_resolution_current);  // cursor avanzó exactamente uno
    ck_assert_int_ne(-1, s.origin_fd);

    // origin_addr se copió una sola vez: la del candidato activo (127.0.0.2:2222)
    struct sockaddr_in *copied = (struct sockaddr_in *)&s.origin_addr;
    ck_assert_uint_eq(inet_addr("127.0.0.2"), copied->sin_addr.s_addr);
    ck_assert_uint_eq(htons(2222), copied->sin_port);
    ck_assert_uint_eq(sizeof(a1), s.origin_addr_len);

    close(s.origin_fd);   // el fd real del 2º candidato quedó abierto
}
END_TEST

START_TEST (test_register_failure_replies_general_failure) {
    // candidato activo pero selector_register falla: no se toca references, el
    // origin_fd se cierra una sola vez y se responde 0x01 → REQUEST_WRITE.
    struct socks5 s;
    memset(&s, 0, sizeof(s));
    init_dest(&s, SOCKS5_ATYP_IPV4, "127.0.0.1", 1111);
    ck_assert_int_eq(0, connect_resolve(&s));   // lista real (liberable)
    s.client_fd  = 100;
    s.origin_fd  = -1;
    s.references = 1;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    g_inject = true; g_connect_fail_until = 0;  // connect activo de entrada
    g_register_fail = true;
    unsigned st = connect_try(&key);

    ck_assert_uint_eq(REQUEST_WRITE, st);
    ck_assert_uint_eq(1, s.references);          // nunca se incrementó
    ck_assert_int_eq(1, g_register_calls);       // un intento
    ck_assert_int_eq(-1, s.origin_fd);           // cerrado, sin double-close
    ck_assert_int_eq(1, g_reply_calls);
    ck_assert_uint_eq(SOCKS5_REP_GENERAL_FAILURE, g_reply_rep);
    ck_assert_ptr_null(s.origin_resolution);     // connect_fail liberó la lista
}
END_TEST

START_TEST (test_setinterest_failure_returns_error) {
    // register OK (references 1→2) pero set_interest(client) falla → ERROR, sin
    // REPLY. El teardown de ambos fds lo hace socksv5_done (nivel servidor).
    struct socks5 s;
    memset(&s, 0, sizeof(s));
    init_dest(&s, SOCKS5_ATYP_IPV4, "127.0.0.1", 1111);
    ck_assert_int_eq(0, connect_resolve(&s));
    s.client_fd  = 100;
    s.origin_fd  = -1;
    s.references = 1;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    g_inject = true; g_connect_fail_until = 0;
    g_setinterest_fail = true;
    unsigned st = connect_try(&key);

    ck_assert_uint_eq(ERROR, st);
    ck_assert_uint_eq(2, s.references);          // register subió references
    ck_assert_int_eq(1, g_register_calls);
    ck_assert_int_ne(-1, s.origin_fd);           // sigue registrado (lo cierra socksv5_done)
    ck_assert_int_eq(0, g_reply_calls);          // no hay REPLY por client_fd roto

    close(s.origin_fd);                          // limpieza del test
    freeaddrinfo(s.origin_resolution);
}
END_TEST

START_TEST (test_getsockopt_failure_returns_error) {
    // getsockopt(-1) falla ⇒ connecting lo trata como error interno: ERROR, sin
    // REPLY y sin avanzar al siguiente candidato.
    struct socks5 s;
    memset(&s, 0, sizeof(s));
    init_dest(&s, SOCKS5_ATYP_IPV4, "127.0.0.1", 1111);
    ck_assert_int_eq(0, connect_resolve(&s));
    struct addrinfo *head = s.origin_resolution_current;
    s.client_fd  = 100;
    s.origin_fd  = -1;   // getsockopt(-1) devuelve -1
    s.references = 2;

    struct selector_key key = { .s = NULL, .fd = s.origin_fd, .data = &s };

    reset_injection();
    unsigned st = connecting(&key);

    ck_assert_uint_eq(ERROR, st);
    ck_assert_int_eq(0, g_reply_calls);                       // no hay REPLY
    ck_assert_ptr_eq(head, s.origin_resolution_current);      // cursor sin avanzar

    freeaddrinfo(s.origin_resolution);
}
END_TEST

START_TEST (test_errno_to_rep) {
    ck_assert_uint_eq(SOCKS5_REP_CONN_REFUSED,        errno_to_rep(ECONNREFUSED));
    ck_assert_uint_eq(SOCKS5_REP_NETWORK_UNREACHABLE, errno_to_rep(ENETUNREACH));
    ck_assert_uint_eq(SOCKS5_REP_HOST_UNREACHABLE,    errno_to_rep(EHOSTUNREACH));
    ck_assert_uint_eq(SOCKS5_REP_HOST_UNREACHABLE,    errno_to_rep(ETIMEDOUT));
    ck_assert_uint_eq(SOCKS5_REP_GENERAL_FAILURE,     errno_to_rep(EACCES));
    ck_assert_uint_eq(SOCKS5_REP_GENERAL_FAILURE,     errno_to_rep(0));
    // no se usa 0x06 (TTL expired) para un timeout de connect
    ck_assert_uint_ne(SOCKS5_REP_TTL_EXPIRED,         errno_to_rep(ETIMEDOUT));
}
END_TEST

START_TEST (test_gai_error_to_rep) {
    // el host que no resuelve → host unreachable
    ck_assert_uint_eq(SOCKS5_REP_HOST_UNREACHABLE, gai_error_to_rep(EAI_NONAME));
    ck_assert_uint_eq(SOCKS5_REP_HOST_UNREACHABLE, gai_error_to_rep(EAI_FAIL));
    // fallos de recurso/internos → general failure
    ck_assert_uint_eq(SOCKS5_REP_GENERAL_FAILURE,  gai_error_to_rep(EAI_MEMORY));
    ck_assert_uint_eq(SOCKS5_REP_GENERAL_FAILURE,  gai_error_to_rep(EAI_SYSTEM));
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("state_connect");
    TCase *tc = tcase_create("connect_resolve");

    tcase_add_test(tc, test_resolve_ipv4_literal);
    tcase_add_test(tc, test_resolve_numerichost_rejects_fqdn);
    tcase_add_test(tc, test_bnd_from_bound_socket);
    tcase_add_test(tc, test_bnd_degrades_on_bad_fd);
    tcase_add_test(tc, test_connect_retry_second_candidate);
    tcase_add_test(tc, test_register_failure_replies_general_failure);
    tcase_add_test(tc, test_setinterest_failure_returns_error);
    tcase_add_test(tc, test_getsockopt_failure_returns_error);
    tcase_add_test(tc, test_errno_to_rep);
    tcase_add_test(tc, test_gai_error_to_rep);
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

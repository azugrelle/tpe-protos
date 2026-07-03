#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <check.h>

// se incluye el .c para poder probar sus funciones estáticas (connect_resolve)
// sin linkear selector.c ni state_request.c: los símbolos externos que referencia
// el módulo se satisfacen con stubs propios (abajo).
#include "states/state_connect.c"

//////////////////////////////////////////////////////////////////////
// Stubs de los símbolos externos que referencia state_connect.c, para que el
// binario linkee sin selector.c / state_request.c. connect_resolve no los usa.

int
request_reply(struct socks5 *s, uint8_t rep, uint8_t bnd_atyp,
              const uint8_t *bnd_addr, uint16_t bnd_port) {
    (void)s; (void)rep; (void)bnd_atyp; (void)bnd_addr; (void)bnd_port;
    return 0;
}

selector_status
selector_set_interest(fd_selector s, int fd, fd_interest i) {
    (void)s; (void)fd; (void)i;
    return SELECTOR_SUCCESS;
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

Suite *
suite(void) {
    Suite *s  = suite_create("state_connect");
    TCase *tc = tcase_create("connect_resolve");

    tcase_add_test(tc, test_resolve_ipv4_literal);
    tcase_add_test(tc, test_resolve_numerichost_rejects_fqdn);
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

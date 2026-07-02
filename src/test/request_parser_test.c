#include <stdlib.h>
#include <string.h>
#include <check.h>

// asi se puede probar las funciones internas
#include "request_parser.c"

#define N(x) (sizeof(x)/sizeof((x)[0]))

/* alimenta `n' bytes de `data' de una sola vez y devuelve el estado final */
static enum request_state
feed_all(struct request_parser *p, const uint8_t *data, size_t n, bool *err) {
    uint8_t raw[512];
    buffer b;
    buffer_init(&b, sizeof(raw), raw);
    memcpy(raw, data, n);
    buffer_write_adv(&b, n);
    return request_consume(&b, p, err);
}

START_TEST (test_request_ipv4) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    uint8_t msg[] = {0x05,0x01,0x00,0x01, 0x7F,0x00,0x00,0x01};
    enum request_state st = feed_all(&p, msg, N(msg), &err);

    ck_assert_int_eq(false, err);
    ck_assert_int_eq(request_dstport, st);
    ck_assert_uint_eq(0x01, p.cmd);
    ck_assert_uint_eq(SOCKS5_ATYP_IPV4, p.atyp);
    ck_assert_uint_eq(4, p.dst_addr_len);
    ck_assert_uint_eq(2, p.remaining);
    ck_assert_uint_eq(0x7F, p.dst_addr[0]);
    ck_assert_uint_eq(0x01, p.dst_addr[3]);
}
END_TEST

START_TEST (test_request_fqdn) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    const char *host = "example.com";
    uint8_t msg[64] = {0x05,0x01,0x00,0x03,(uint8_t)strlen(host)};
    memcpy(msg + 5, host, strlen(host));
    enum request_state st = feed_all(&p, msg, 5 + strlen(host), &err);

    ck_assert_int_eq(false, err);
    ck_assert_int_eq(request_dstport, st);
    ck_assert_uint_eq(SOCKS5_ATYP_DOMAIN, p.atyp);
    ck_assert_uint_eq(strlen(host), p.dst_addr_len);
    ck_assert_int_eq(0, memcmp(p.dst_addr, host, strlen(host)));
}
END_TEST

START_TEST (test_request_ipv6) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    uint8_t msg[4 + 16] = {0x05,0x01,0x00,0x04};
    msg[4 + 15] = 0x01;  // ::1
    enum request_state st = feed_all(&p, msg, N(msg), &err);

    ck_assert_int_eq(false, err);
    ck_assert_int_eq(request_dstport, st);
    ck_assert_uint_eq(SOCKS5_ATYP_IPV6, p.atyp);
    ck_assert_uint_eq(16, p.dst_addr_len);
}
END_TEST

START_TEST (test_request_bad_version) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    uint8_t msg[] = {0x04,0x01,0x00,0x01};
    enum request_state st = feed_all(&p, msg, N(msg), &err);

    ck_assert_int_eq(true, err);
    ck_assert_int_eq(request_error_unsupported_version, st);
}
END_TEST

START_TEST (test_request_unsupported_cmd) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    uint8_t msg[] = {0x05,0x02,0x00,0x01};  // BIND
    enum request_state st = feed_all(&p, msg, N(msg), &err);

    ck_assert_int_eq(true, err);
    ck_assert_int_eq(request_error_unsupported_cmd, st);
    ck_assert_uint_eq(0x02, p.cmd);
}
END_TEST

START_TEST (test_request_unsupported_atyp) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    uint8_t msg[] = {0x05,0x01,0x00,0x09};
    enum request_state st = feed_all(&p, msg, N(msg), &err);

    ck_assert_int_eq(true, err);
    ck_assert_int_eq(request_error_unsupported_atyp, st);
}
END_TEST

START_TEST (test_request_fragmented) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    uint8_t a[] = {0x05,0x01};
    uint8_t b[] = {0x00,0x01,0x7F};
    uint8_t c[] = {0x00,0x00,0x01};
    feed_all(&p, a, N(a), &err);
    feed_all(&p, b, N(b), &err);
    enum request_state st = feed_all(&p, c, N(c), &err);

    ck_assert_int_eq(false, err);
    ck_assert_int_eq(request_dstport, st);
    ck_assert_uint_eq(4, p.dst_addr_len);
    ck_assert_uint_eq(0x7F, p.dst_addr[0]);
}
END_TEST

START_TEST (test_request_empty_fqdn) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    uint8_t msg[] = {0x05,0x01,0x00,0x03,0x00};  // FQDN de longitud 0
    enum request_state st = feed_all(&p, msg, N(msg), &err);

    ck_assert_int_eq(true, err);
    ck_assert_int_eq(request_error_invalid, st);
}
END_TEST

START_TEST (test_request_ipv4_full) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    // 1.2.3.4 : 8080  (0x1F90)
    uint8_t msg[] = {0x05,0x01,0x00,0x01, 0x01,0x02,0x03,0x04, 0x1F,0x90};
    enum request_state st = feed_all(&p, msg, N(msg), &err);

    ck_assert_int_eq(false, err);
    ck_assert_int_eq(request_done, st);
    ck_assert_uint_eq(0, p.remaining);
    ck_assert_uint_eq(8080, p.dst_port);
}
END_TEST

START_TEST (test_request_fqdn_full) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    const char *host = "example.com";
    uint8_t msg[64] = {0x05,0x01,0x00,0x03,(uint8_t)strlen(host)};
    memcpy(msg + 5, host, strlen(host));
    size_t off = 5 + strlen(host);
    msg[off] = 0x00; msg[off+1] = 0x50;  // puerto 80
    enum request_state st = feed_all(&p, msg, off + 2, &err);

    ck_assert_int_eq(false, err);
    ck_assert_int_eq(request_done, st);
    ck_assert_uint_eq(80, p.dst_port);
    ck_assert_int_eq(0, memcmp(p.dst_addr, host, strlen(host)));
}
END_TEST

START_TEST (test_request_port_fragmented) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    // el puerto llega partido entre dos "recv"
    uint8_t a[] = {0x05,0x01,0x00,0x01, 0x7F,0x00,0x00,0x01, 0x1F};
    uint8_t b[] = {0x90};
    ck_assert_int_eq(request_dstport, feed_all(&p, a, N(a), &err));
    enum request_state st = feed_all(&p, b, N(b), &err);

    ck_assert_int_eq(false, err);
    ck_assert_int_eq(request_done, st);
    ck_assert_uint_eq(8080, p.dst_port);
}
END_TEST

START_TEST (test_addr_to_string_ipv4) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    uint8_t msg[] = {0x05,0x01,0x00,0x01, 0x01,0x02,0x03,0x04, 0x00,0x50};
    feed_all(&p, msg, N(msg), &err);

    char host[64];
    ck_assert_int_eq(0, request_addr_to_string(&p, host, sizeof(host)));
    ck_assert_str_eq("1.2.3.4", host);
}
END_TEST

START_TEST (test_addr_to_string_fqdn) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    const char *h = "example.com";
    uint8_t msg[64] = {0x05,0x01,0x00,0x03,(uint8_t)strlen(h)};
    memcpy(msg + 5, h, strlen(h));
    size_t off = 5 + strlen(h);
    msg[off] = 0x00; msg[off+1] = 0x50;
    feed_all(&p, msg, off + 2, &err);

    char host[64];
    ck_assert_int_eq(0, request_addr_to_string(&p, host, sizeof(host)));
    ck_assert_str_eq("example.com", host);
}
END_TEST

START_TEST (test_addr_to_string_ipv6_pending) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    uint8_t msg[4 + 16 + 2] = {0x05,0x01,0x00,0x04};
    msg[4 + 15] = 0x01;  // ::1
    feed_all(&p, msg, N(msg), &err);

    char host[64];
    // IPv6 todavía no se reconstruye en M1 (T52).
    ck_assert_int_eq(-1, request_addr_to_string(&p, host, sizeof(host)));
}
END_TEST

START_TEST (test_addr_to_string_no_space) {
    struct request_parser p;
    request_parser_init(&p);
    bool err = false;
    const char *h = "example.com";
    uint8_t msg[64] = {0x05,0x01,0x00,0x03,(uint8_t)strlen(h)};
    memcpy(msg + 5, h, strlen(h));
    size_t off = 5 + strlen(h);
    msg[off] = 0x00; msg[off+1] = 0x50;
    feed_all(&p, msg, off + 2, &err);

    char host[4];  // no entra "example.com" + NUL
    ck_assert_int_eq(-1, request_addr_to_string(&p, host, sizeof(host)));
}
END_TEST

START_TEST (test_marshall_success_ipv4) {
    uint8_t raw[32];
    buffer b;
    buffer_init(&b, sizeof(raw), raw);
    uint8_t bnd[4] = {0,0,0,0};
    int n = request_marshall(&b, SOCKS5_REP_SUCCEEDED, SOCKS5_ATYP_IPV4, bnd, 0);

    ck_assert_int_eq(10, n);  // 4 + 4 + 2
    size_t avail;
    uint8_t *out = buffer_read_ptr(&b, &avail);
    ck_assert_uint_eq(10, avail);
    uint8_t expected[] = {0x05,0x00,0x00,0x01, 0,0,0,0, 0,0};
    ck_assert_int_eq(0, memcmp(out, expected, sizeof(expected)));
}
END_TEST

START_TEST (test_marshall_port_network_order) {
    uint8_t raw[32];
    buffer b;
    buffer_init(&b, sizeof(raw), raw);
    uint8_t bnd[4] = {1,2,3,4};
    int n = request_marshall(&b, SOCKS5_REP_SUCCEEDED, SOCKS5_ATYP_IPV4, bnd, 8080);

    ck_assert_int_eq(10, n);
    size_t avail;
    uint8_t *out = buffer_read_ptr(&b, &avail);
    // BND.PORT en big-endian: 8080 = 0x1F90
    ck_assert_uint_eq(0x1F, out[8]);
    ck_assert_uint_eq(0x90, out[9]);
    ck_assert_uint_eq(0x01, out[4]);  // BND.ADDR
    ck_assert_uint_eq(0x04, out[7]);
}
END_TEST

START_TEST (test_marshall_ipv6_len) {
    uint8_t raw[64];
    buffer b;
    buffer_init(&b, sizeof(raw), raw);
    uint8_t bnd[16] = {0};
    int n = request_marshall(&b, SOCKS5_REP_SUCCEEDED, SOCKS5_ATYP_IPV6, bnd, 0);

    ck_assert_int_eq(22, n);  // 4 + 16 + 2
}
END_TEST

START_TEST (test_marshall_no_space) {
    uint8_t raw[6];  // no entran 10 bytes
    buffer b;
    buffer_init(&b, sizeof(raw), raw);
    uint8_t bnd[4] = {0};
    ck_assert_int_eq(-1, request_marshall(&b, SOCKS5_REP_SUCCEEDED, SOCKS5_ATYP_IPV4, bnd, 0));
}
END_TEST

START_TEST (test_marshall_bad_atyp) {
    uint8_t raw[32];
    buffer b;
    buffer_init(&b, sizeof(raw), raw);
    uint8_t bnd[4] = {0};
    // ATYP DOMAIN no es válido en el BND de la respuesta.
    ck_assert_int_eq(-1, request_marshall(&b, SOCKS5_REP_SUCCEEDED, SOCKS5_ATYP_DOMAIN, bnd, 0));
}
END_TEST

Suite *
suite(void) {
    Suite *s   = suite_create("request_parser");
    TCase *tc  = tcase_create("request_parser");

    tcase_add_test(tc, test_request_ipv4);
    tcase_add_test(tc, test_request_fqdn);
    tcase_add_test(tc, test_request_ipv6);
    tcase_add_test(tc, test_request_bad_version);
    tcase_add_test(tc, test_request_unsupported_cmd);
    tcase_add_test(tc, test_request_unsupported_atyp);
    tcase_add_test(tc, test_request_fragmented);
    tcase_add_test(tc, test_request_empty_fqdn);
    tcase_add_test(tc, test_request_ipv4_full);
    tcase_add_test(tc, test_request_fqdn_full);
    tcase_add_test(tc, test_request_port_fragmented);
    tcase_add_test(tc, test_addr_to_string_ipv4);
    tcase_add_test(tc, test_addr_to_string_fqdn);
    tcase_add_test(tc, test_addr_to_string_ipv6_pending);
    tcase_add_test(tc, test_addr_to_string_no_space);
    tcase_add_test(tc, test_marshall_success_ipv4);
    tcase_add_test(tc, test_marshall_port_network_order);
    tcase_add_test(tc, test_marshall_ipv6_len);
    tcase_add_test(tc, test_marshall_no_space);
    tcase_add_test(tc, test_marshall_bad_atyp);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void) {
    SRunner *sr  = srunner_create(suite());
    int number_failed;

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

// se incluye el .c para poder resetear el estado global entre tests sin
// exponer un reset dedicado en la API pública.
#include "metrics.c"

START_TEST (test_access_log_empty_when_no_visits) {
    metrics_init();

    char lines[4][ACCESS_LOG_LINE_LEN];
    int n = metrics_get_access_log(NULL, lines, 4);

    ck_assert_int_eq(0, n);

    metrics_free();
}
END_TEST

START_TEST (test_access_log_formats_line) {
    metrics_init();

    metrics_add_user_site("alice", "www.google.com", "80", true);

    char lines[4][ACCESS_LOG_LINE_LEN];
    int n = metrics_get_access_log(NULL, lines, 4);

    ck_assert_int_eq(1, n);

    char user[MAX_USERNAME_LEN], host_port[300], ts[64], status[16];
    int fields = sscanf(lines[0], "%255s %299s %63s %15s", user, host_port, ts, status);
    ck_assert_int_eq(4, fields);
    ck_assert_str_eq("alice", user);
    ck_assert_str_eq("www.google.com:80", host_port);
    ck_assert_str_eq("SUCCESS", status);
    // ISO8601 UTC: YYYY-MM-DDThh:mm:ssZ (20 caracteres)
    ck_assert_int_eq(20, (int)strlen(ts));
    ck_assert_int_eq('Z', ts[19]);

    metrics_free();
}
END_TEST

START_TEST (test_access_log_marks_failure) {
    metrics_init();

    metrics_add_user_site("bob", "unreachable.example", "443", false);

    char lines[4][ACCESS_LOG_LINE_LEN];
    int n = metrics_get_access_log(NULL, lines, 4);

    ck_assert_int_eq(1, n);
    ck_assert_ptr_nonnull(strstr(lines[0], " FAIL"));
    ck_assert_ptr_null(strstr(lines[0], "SUCCESS"));

    metrics_free();
}
END_TEST

START_TEST (test_access_log_filters_by_username) {
    metrics_init();

    metrics_add_user_site("alice", "a.example", "80", true);
    metrics_add_user_site("bob",   "b.example", "80", true);
    metrics_add_user_site("alice", "c.example", "80", false);

    char lines[8][ACCESS_LOG_LINE_LEN];
    int n = metrics_get_access_log("alice", lines, 8);

    ck_assert_int_eq(2, n);
    for (int i = 0; i < n; i++) {
        ck_assert_ptr_nonnull(strstr(lines[i], "alice "));
    }

    metrics_free();
}
END_TEST

START_TEST (test_access_log_unknown_user_returns_none) {
    metrics_init();

    metrics_add_user_site("alice", "a.example", "80", true);

    char lines[4][ACCESS_LOG_LINE_LEN];
    int n = metrics_get_access_log("nobody", lines, 4);

    ck_assert_int_eq(0, n);

    metrics_free();
}
END_TEST

START_TEST (test_access_log_respects_max) {
    metrics_init();

    metrics_add_user_site("alice", "a1.example", "80", true);
    metrics_add_user_site("alice", "a2.example", "80", true);
    metrics_add_user_site("alice", "a3.example", "80", true);

    char lines[2][ACCESS_LOG_LINE_LEN];
    int n = metrics_get_access_log(NULL, lines, 2);

    ck_assert_int_eq(2, n);

    metrics_free();
}
END_TEST

START_TEST (test_access_log_sanitizes_framing_bytes) {
    metrics_init();

    // defensa en profundidad: aunque el parser del REQUEST ya rechaza estos
    // bytes, un destino con '\n' o espacios no debe poder cortar líneas ni
    // agregar campos en la respuesta multilínea del monitoreo.
    metrics_add_user_site("alice", "evil\nfake.example 80", "80", true);

    char lines[4][ACCESS_LOG_LINE_LEN];
    int n = metrics_get_access_log(NULL, lines, 4);

    ck_assert_int_eq(1, n);
    ck_assert_ptr_null(strchr(lines[0], '\n'));
    ck_assert_ptr_nonnull(strstr(lines[0], "evil?fake.example?80:80"));

    metrics_free();
}
END_TEST

START_TEST (test_no_active_users_initially) {
    metrics_init();

    ck_assert_int_eq(0, metrics_get_user_count());

    metrics_free();
}
END_TEST

START_TEST (test_add_user_becomes_active) {
    metrics_init();

    metrics_add_user("alice");

    ck_assert_int_eq(1, metrics_get_user_count());
    user_info u;
    metrics_get_users(&u, 1);
    ck_assert_str_eq("alice", u.username);

    metrics_free();
}
END_TEST

START_TEST (test_remove_user_leaves_actives) {
    metrics_init();

    metrics_add_user("alice");
    metrics_remove_user("alice");

    ck_assert_int_eq(0, metrics_get_user_count());

    metrics_free();
}
END_TEST

START_TEST (test_remove_unknown_user_is_noop) {
    metrics_init();

    metrics_add_user("alice");
    metrics_remove_user("nobody");

    ck_assert_int_eq(1, metrics_get_user_count());

    metrics_free();
}
END_TEST

START_TEST (test_same_user_twice_single_entry) {
    metrics_init();

    metrics_add_user("alice");
    metrics_add_user("alice");

    ck_assert_int_eq(1, metrics_get_user_count());

    metrics_free();
}
END_TEST

START_TEST (test_user_active_until_last_connection_dies) {
    metrics_init();

    // dos conexiones del mismo usuario: la primera desconexión no debe
    // sacarlo de los activos, la segunda sí
    metrics_add_user("alice");
    metrics_add_user("alice");

    metrics_remove_user("alice");
    ck_assert_int_eq(1, metrics_get_user_count());
    user_info u;
    metrics_get_users(&u, 1);
    ck_assert_str_eq("alice", u.username);

    metrics_remove_user("alice");
    ck_assert_int_eq(0, metrics_get_user_count());

    metrics_free();
}
END_TEST

START_TEST (test_remove_compacts_without_mixing_counts) {
    metrics_init();

    // bob (2 conexiones) queda último en el arreglo; al morir alice, bob se
    // mueve a su hueco y tiene que conservar SU contador: una desconexión de
    // bob no debe eliminarlo todavía
    metrics_add_user("alice");
    metrics_add_user("bob");
    metrics_add_user("bob");

    metrics_remove_user("alice");
    ck_assert_int_eq(1, metrics_get_user_count());

    metrics_remove_user("bob");
    ck_assert_int_eq(1, metrics_get_user_count());
    user_info u;
    metrics_get_users(&u, 1);
    ck_assert_str_eq("bob", u.username);

    metrics_remove_user("bob");
    ck_assert_int_eq(0, metrics_get_user_count());

    metrics_free();
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("metrics");
    TCase *tc = tcase_create("access_log");

    tcase_add_test(tc, test_access_log_empty_when_no_visits);
    tcase_add_test(tc, test_access_log_formats_line);
    tcase_add_test(tc, test_access_log_marks_failure);
    tcase_add_test(tc, test_access_log_filters_by_username);
    tcase_add_test(tc, test_access_log_unknown_user_returns_none);
    tcase_add_test(tc, test_access_log_respects_max);
    tcase_add_test(tc, test_access_log_sanitizes_framing_bytes);
    suite_add_tcase(s, tc);

    TCase *tc_active = tcase_create("active_users");
    tcase_add_test(tc_active, test_no_active_users_initially);
    tcase_add_test(tc_active, test_add_user_becomes_active);
    tcase_add_test(tc_active, test_remove_user_leaves_actives);
    tcase_add_test(tc_active, test_remove_unknown_user_is_noop);
    tcase_add_test(tc_active, test_same_user_twice_single_entry);
    tcase_add_test(tc_active, test_user_active_until_last_connection_dies);
    tcase_add_test(tc_active, test_remove_compacts_without_mixing_counts);
    suite_add_tcase(s, tc_active);

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

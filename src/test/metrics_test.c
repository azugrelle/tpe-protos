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

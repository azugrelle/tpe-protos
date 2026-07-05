#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

// se incluyen los .c para poder ejercitar internals (_hash) y resetear el
// estado global (user_credentials) entre tests, igual que metrics_test.c.
#include "../server/utils/hashmap.c"
#include "../server/utils/user_auth_utils.c"

/** busca `want' keys "k<n>" cuyo hash caiga en el bucket 0 de una tabla de
 *  `capacity' slots: da un cluster determinístico para probar hashmap_delete
 *  sin depender de conocer de antemano los valores de _hash. */
static void
find_colliding_keys(size_t capacity, size_t want, char keys[][32]) {
    size_t found = 0;
    for (int i = 0; found < want && i < 1000000; i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), "k%d", i);
        if (_hash(buf) % capacity == 0) {
            strcpy(keys[found], buf);
            found++;
        }
    }
    ck_assert_uint_eq(want, found);
}

START_TEST (test_hashmap_delete_preserves_cluster_probing) {
    hashmap_t *map = hashmap_create(4);
    char keys[3][32];
    find_colliding_keys(4, 3, keys);

    ck_assert_int_ne(0, hashmap_insert(map, keys[0], "va", 0));
    ck_assert_int_ne(0, hashmap_insert(map, keys[1], "vb", 0));
    ck_assert_int_ne(0, hashmap_insert(map, keys[2], "vc", 0));

    // borrar la cabeza del cluster no debe romper el probing de lo que sigue
    ck_assert_int_eq(1, hashmap_delete(map, keys[0]));

    ck_assert_ptr_null(hashmap_get(map, keys[0]));
    ck_assert_ptr_nonnull(hashmap_get(map, keys[1]));
    ck_assert_ptr_nonnull(hashmap_get(map, keys[2]));
    ck_assert_str_eq("vb", hashmap_get(map, keys[1])->value);
    ck_assert_str_eq("vc", hashmap_get(map, keys[2])->value);

    hashmap_destroy(map);
}
END_TEST

START_TEST (test_hashmap_delete_unknown_key_returns_zero) {
    hashmap_t *map = hashmap_create(4);
    ck_assert_int_eq(0, hashmap_delete(map, "nobody"));
    hashmap_destroy(map);
}
END_TEST

START_TEST (test_add_user_ok) {
    free_user_credentials();

    ck_assert_int_eq(USER_ADD_OK, add_user_credentials("carol", "pw123"));
    ck_assert_uint_eq(0x00, check_if_valid_credentials("carol", "pw123"));

    free_user_credentials();
}
END_TEST

START_TEST (test_add_user_exists) {
    free_user_credentials();
    create_user_credentials("bob", "1234", false);

    ck_assert_int_eq(USER_ADD_EXISTS, add_user_credentials("bob", "otherpass"));

    free_user_credentials();
}
END_TEST

START_TEST (test_add_user_invalid) {
    free_user_credentials();

    ck_assert_int_eq(USER_ADD_INVALID, add_user_credentials("bad user!", "pw"));
    ck_assert_int_eq(USER_ADD_INVALID, add_user_credentials("", "pw"));
    ck_assert_int_eq(USER_ADD_INVALID, add_user_credentials("user", ""));

    free_user_credentials();
}
END_TEST

START_TEST (test_add_user_table_full) {
    free_user_credentials();

    char name[16];
    for (int i = 0; i < MAX_USERS; i++) {
        snprintf(name, sizeof(name), "user%d", i);
        ck_assert_int_eq(USER_ADD_OK, add_user_credentials(name, "pw"));
    }
    ck_assert_int_eq(USER_ADD_FULL, add_user_credentials("oneMore", "pw"));

    free_user_credentials();
}
END_TEST

START_TEST (test_delete_user_blocks_future_auth) {
    free_user_credentials();
    create_user_credentials("admin", "adminpw", true);
    create_user_credentials("bob", "1234", false);

    ck_assert_int_eq(USER_DEL_OK, delete_user_credentials("bob"));
    ck_assert_uint_eq(0x01, check_if_valid_credentials("bob", "1234"));

    free_user_credentials();
}
END_TEST

START_TEST (test_delete_user_not_found) {
    free_user_credentials();

    ck_assert_int_eq(USER_DEL_NOT_FOUND, delete_user_credentials("ghost"));

    free_user_credentials();
}
END_TEST

START_TEST (test_delete_last_admin_is_protected) {
    free_user_credentials();
    create_user_credentials("admin", "adminpw", true);

    ck_assert_int_eq(USER_DEL_LAST_ADMIN, delete_user_credentials("admin"));
    // sigue vivo: ni se borró ni perdió el flag de admin
    ck_assert_uint_eq(0x00, check_if_valid_admin_credentials("admin", "adminpw"));

    free_user_credentials();
}
END_TEST

START_TEST (test_delete_second_admin_allowed) {
    free_user_credentials();
    create_user_credentials("admin1", "pw1", true);
    create_user_credentials("admin2", "pw2", true);

    ck_assert_int_eq(USER_DEL_OK, delete_user_credentials("admin1"));
    // ahora admin2 es el último admin
    ck_assert_int_eq(USER_DEL_LAST_ADMIN, delete_user_credentials("admin2"));

    free_user_credentials();
}
END_TEST

START_TEST (test_check_valid_admin_credentials_rejects_non_admin) {
    free_user_credentials();
    create_user_credentials("admin", "adminpw", true);
    create_user_credentials("bob", "1234", false);

    ck_assert_uint_eq(0x00, check_if_valid_admin_credentials("admin", "adminpw"));
    ck_assert_uint_eq(0x01, check_if_valid_admin_credentials("bob", "1234"));

    free_user_credentials();
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("hashmap_user_auth");
    TCase *tc = tcase_create("hashmap");

    tcase_add_test(tc, test_hashmap_delete_preserves_cluster_probing);
    tcase_add_test(tc, test_hashmap_delete_unknown_key_returns_zero);
    tcase_add_test(tc, test_add_user_ok);
    tcase_add_test(tc, test_add_user_exists);
    tcase_add_test(tc, test_add_user_invalid);
    tcase_add_test(tc, test_add_user_table_full);
    tcase_add_test(tc, test_delete_user_blocks_future_auth);
    tcase_add_test(tc, test_delete_user_not_found);
    tcase_add_test(tc, test_delete_last_admin_is_protected);
    tcase_add_test(tc, test_delete_second_admin_allowed);
    tcase_add_test(tc, test_check_valid_admin_credentials_rejects_non_admin);
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

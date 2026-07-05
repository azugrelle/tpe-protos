#include <stdlib.h>
#include <check.h>

#define INITIAL_SIZE ((size_t) 1024)

// para poder testear las funciones estaticas
#include "selector.c"

START_TEST (test_selector_error) {
    const selector_status data[] = {
        SELECTOR_SUCCESS,
        SELECTOR_ENOMEM,
        SELECTOR_MAXFD,
        SELECTOR_IARGS,
        SELECTOR_IO,
    };
    // verifica que `selector_error' tiene mensajes especificos
    for(unsigned i = 0 ; i < N(data); i++) {
        ck_assert_str_ne(ERROR_DEFAULT_MSG, selector_error(data[i]));
    }
}
END_TEST

START_TEST (test_next_capacity) {
    const size_t data[] = {
         0,  1,
         1,  2,
         2,  4,
         3,  4,
         4,  8,
         7,  8,
         8, 16,
        15, 16,
        31, 32,
        16, 32,
        ITEMS_MAX_SIZE, ITEMS_MAX_SIZE,
        ITEMS_MAX_SIZE + 1, ITEMS_MAX_SIZE,
    };
    for(unsigned i = 0; i < N(data) / 2; i++ ) {
        ck_assert_uint_eq(data[i * 2 + 1] + 1, next_capacity(data[i*2]));
    }
}
END_TEST

START_TEST (test_ensure_capacity) {
    fd_selector s = selector_new(0);
    for(size_t i = 0; i < s->fd_size; i++) {
        ck_assert_int_eq(FD_UNUSED, s->fds[i].fd);
    }

    size_t n = 1;
    ck_assert_int_eq(SELECTOR_SUCCESS, ensure_capacity(s, n));
    ck_assert_uint_ge(s->fd_size, n);

    n = 10;
    ck_assert_int_eq(SELECTOR_SUCCESS, ensure_capacity(s, n));
    ck_assert_uint_ge(s->fd_size, n);

    const size_t last_size = s->fd_size;
    n = ITEMS_MAX_SIZE + 1;
    ck_assert_int_eq(SELECTOR_MAXFD, ensure_capacity(s, n));
    ck_assert_uint_eq(last_size, s->fd_size);

    for(size_t i = 0; i < s->fd_size; i++) {
        ck_assert_int_eq(FD_UNUSED, s->fds[i].fd);
    }

    selector_destroy(s);

    ck_assert_ptr_null(selector_new(ITEMS_MAX_SIZE + 1));
}
END_TEST

// callbacks de prueba
static void *data_mark = (void *)0x0FF1CE;
static unsigned destroy_count = 0;
static void
destroy_callback(struct selector_key *key) {
    ck_assert_ptr_nonnull(key->s);
    ck_assert_int_ge(key->fd, 0);
    ck_assert_int_lt(key->fd, ITEMS_MAX_SIZE);

    ck_assert_ptr_eq(data_mark, key->data);
    destroy_count++;
}

START_TEST (test_selector_register_fd) {
    destroy_count = 0;
    fd_selector s = selector_new(INITIAL_SIZE);
    ck_assert_ptr_nonnull(s);

    ck_assert_uint_eq(SELECTOR_IARGS,   selector_register(0, -1, 0, 0, data_mark));

    const struct fd_handler h = {
        .handle_read   = NULL,
        .handle_write  = NULL,
        .handle_close  = destroy_callback,
    };
    int fd = ITEMS_MAX_SIZE - 1;
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    const struct item *item = s->fds + fd;
    ck_assert_int_eq (fd,         s->max_fd);
    ck_assert_int_eq (fd,         item->fd);
    ck_assert_ptr_eq (&h,         item->handler);
    ck_assert_uint_eq(0,          item->interest);
    ck_assert_ptr_eq (data_mark,  item->data);

    selector_destroy(s);
    // destroy desregistró?
    ck_assert_uint_eq(1,          destroy_count);

}
END_TEST

START_TEST (test_selector_register_unregister_register) {
    destroy_count = 0;
    fd_selector s = selector_new(INITIAL_SIZE);
    ck_assert_ptr_nonnull(s);

    const struct fd_handler h = {
        .handle_read   = NULL,
        .handle_write  = NULL,
        .handle_close  = destroy_callback,
    };
    int fd = ITEMS_MAX_SIZE - 1;
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_unregister_fd(s, fd));

    const struct item *item = s->fds + fd;
    ck_assert_int_eq (0,          s->max_fd);
    ck_assert_int_eq (FD_UNUSED,  item->fd);
    ck_assert_ptr_eq (0x00,       item->handler);
    ck_assert_uint_eq(0,          item->interest);
    ck_assert_ptr_eq (0x00,       item->data);

    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    item = s->fds + fd;
    ck_assert_int_eq (fd,         s->max_fd);
    ck_assert_int_eq (fd,         item->fd);
    ck_assert_ptr_eq (&h,         item->handler);
    ck_assert_uint_eq(0,          item->interest);
    ck_assert_ptr_eq (data_mark,  item->data);

    selector_destroy(s);
    ck_assert_uint_eq(2,          destroy_count);

}
END_TEST

static unsigned block_count = 0;
static void
block_callback(struct selector_key *key) {
    ck_assert_ptr_eq(data_mark, key->data);
    block_count++;
}

START_TEST (test_notify_block_job) {
    // el notify termina en pthread_kill(selector_thread, conf.signal): hace
    // falta la señal configurada (con su handler no-op) y un thread real.
    const struct selector_init init_conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 1, .tv_nsec = 0 },
    };
    ck_assert_int_eq(0, selector_init(&init_conf));

    destroy_count = 0;
    block_count   = 0;
    fd_selector s = selector_new(INITIAL_SIZE);
    ck_assert_ptr_nonnull(s);
    s->selector_thread = pthread_self();

    const struct fd_handler h = {
        .handle_close = destroy_callback,
        .handle_block = block_callback,
    };
    const int fd = 42;
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));

    // job embebido (heap = false): se despacha y el selector no lo libera
    struct blocking_job job;
    memset(&job, 0, sizeof(job));
    ck_assert_uint_eq(SELECTOR_SUCCESS, selector_notify_block_job(s, fd, &job));
    ck_assert_ptr_eq(&job, s->resolution_jobs);
    handle_block_notifications(s);
    ck_assert_uint_eq(1, block_count);
    ck_assert_ptr_null(s->resolution_jobs);

    // el mismo job embebido se puede reusar para otra notificación
    ck_assert_uint_eq(SELECTOR_SUCCESS, selector_notify_block_job(s, fd, &job));
    handle_block_notifications(s);
    ck_assert_uint_eq(2, block_count);

    // el wrapper histórico (job del heap) sigue andando
    ck_assert_uint_eq(SELECTOR_SUCCESS, selector_notify_block(s, fd));
    handle_block_notifications(s);
    ck_assert_uint_eq(3, block_count);

    // un embebido pendiente al destruir: el drenaje corre antes del
    // unregister y no hace free de memoria que no es suya
    ck_assert_uint_eq(SELECTOR_SUCCESS, selector_notify_block_job(s, fd, &job));
    selector_destroy(s);
    ck_assert_uint_eq(1, destroy_count);
}
END_TEST

// Verifica que el drenaje NO sostiene resolution_mutex mientras despacha.
// Reentra al mutex igual que lo haría un callback real que reencola una
// notificación o desregistra su conexión. Si el drenaje lo tuviera tomado,
// este lock (mismo hilo, mutex no recursivo) deadlockearía; con la cola ya
// desligada sólo espera brevemente a que un productor lo suelte. No se puede
// usar trylock: un productor concurrente puede tener el mutex y devolver EBUSY
// sin que eso implique que el drenaje lo tenga.
static void
block_mutex_check_callback(struct selector_key *key) {
    ck_assert_ptr_eq(data_mark, key->data);
    pthread_mutex_lock(&key->s->resolution_mutex);
    pthread_mutex_unlock(&key->s->resolution_mutex);
    block_count++;
}

#define CONC_PRODUCERS ((unsigned) 4)
#define CONC_PER_THREAD ((unsigned) 250)

struct producer_arg {
    fd_selector s;
    int         fd;
};

static void *
notify_producer(void *p) {
    struct producer_arg *a = p;
    for(unsigned i = 0; i < CONC_PER_THREAD; i++) {
        // wrapper del heap: ejercita malloc/free del job bajo contención
        selector_notify_block(a->s, a->fd);
    }
    return NULL;
}

// Varios hilos encolan notificaciones mientras el hilo principal drena. Se
// ejercita la contención sobre resolution_mutex y, en cada dispatch, se
// verifica que el mutex está libre (block_mutex_check_callback). El total de
// callbacks debe coincidir exactamente con lo encolado.
START_TEST (test_notify_block_concurrent) {
    const struct selector_init init_conf = {
        .signal         = SIGALRM,
        .select_timeout = { .tv_sec = 1, .tv_nsec = 0 },
    };
    ck_assert_int_eq(0, selector_init(&init_conf));

    destroy_count = 0;
    block_count   = 0;
    fd_selector s = selector_new(INITIAL_SIZE);
    ck_assert_ptr_nonnull(s);
    s->selector_thread = pthread_self();

    const struct fd_handler h = {
        .handle_close = destroy_callback,
        .handle_block = block_mutex_check_callback,
    };
    const int fd = 42;
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));

    pthread_t          th[CONC_PRODUCERS];
    struct producer_arg args[CONC_PRODUCERS];
    for(unsigned i = 0; i < CONC_PRODUCERS; i++) {
        args[i].s  = s;
        args[i].fd = fd;
        ck_assert_int_eq(0, pthread_create(&th[i], NULL, notify_producer,
                                           &args[i]));
    }

    const unsigned total = CONC_PRODUCERS * CONC_PER_THREAD;
    // drena mientras los productores siguen encolando
    while(block_count < total) {
        handle_block_notifications(s);
    }

    for(unsigned i = 0; i < CONC_PRODUCERS; i++) {
        ck_assert_int_eq(0, pthread_join(th[i], NULL));
    }
    // drenaje final por si algo quedó encolado tras el último chequeo
    handle_block_notifications(s);

    ck_assert_uint_eq(total, block_count);
    ck_assert_ptr_null(s->resolution_jobs);

    selector_destroy(s);
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("nio");
    TCase *tc = tcase_create("nio");

    tcase_add_test(tc, test_next_capacity);
    tcase_add_test(tc, test_selector_error);
    tcase_add_test(tc, test_ensure_capacity);
    tcase_add_test(tc, test_selector_register_fd);
    tcase_add_test(tc, test_selector_register_unregister_register);
    tcase_add_test(tc, test_notify_block_job);
    tcase_add_test(tc, test_notify_block_concurrent);
    // si una regresión hiciera que el drenaje sostenga resolution_mutex
    // durante el dispatch, el callback reentrante deadlockea: acotamos la
    // espera para que falle por timeout en vez de colgarse.
    tcase_set_timeout(tc, 10);
    suite_add_tcase(s, tc);

    return s;
}

int 
main(void) {
    int number_failed;
    SRunner *sr = srunner_create(suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


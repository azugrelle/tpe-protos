/*
 * Shim LD_PRELOAD para simular DNS lento de forma determinística: un host
 * que contenga "slow" duerme 3 segundos y después resuelve como localhost;
 * el resto pasa directo al getaddrinfo real.
 *
 * Lo usa leak_resolving_teardown.sh para garantizar que el SIGTERM agarre al
 * server con resoluciones en vuelo: si el apagado no esperara a los hilos de
 * DNS, el hilo tardío escribiría sobre memoria liberada y valgrind lo
 * reportaría como invalid write.
 *
 * Compilar con: gcc -shared -fPIC -o slowdns_shim.so slowdns_shim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

static int (*real_getaddrinfo)(const char *, const char *,
                               const struct addrinfo *, struct addrinfo **);
static pthread_once_t resolve_real_once = PTHREAD_ONCE_INIT;

static void
resolve_real(void) {
    real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
}

int
getaddrinfo(const char *node, const char *service,
            const struct addrinfo *hints, struct addrinfo **res) {
    pthread_once(&resolve_real_once, resolve_real);
    if(node != NULL && strstr(node, "slow") != NULL) {
        sleep(3);
        return real_getaddrinfo("localhost", service, hints, res);
    }
    return real_getaddrinfo(node, service, hints, res);
}

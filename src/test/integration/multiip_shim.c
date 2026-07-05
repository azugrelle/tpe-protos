/*
 * Shim LD_PRELOAD para simular un FQDN multi-IP con direcciones caídas de
 * forma determinística:
 *
 *   - nombre que contiene "fallback"   → [127.0.0.2:puerto, 127.0.0.1:puerto]
 *   - nombre que contiene "allrefused" → [127.0.0.2:puerto, 127.0.0.3:puerto]
 *   - cualquier otro nombre            → getaddrinfo real
 *
 * "IP caída" = otra dirección de loopback con el MISMO puerto: el test ata su
 * servidor de origen solo a 127.0.0.1, así que 127.0.0.2/3 rechazan con
 * ECONNREFUSED inmediato (en Linux todo 127.0.0.0/8 vive en lo). Eso prueba
 * fallback entre direcciones de verdad — no entre puertos — sin esperas, sin
 * root y sin tocar /etc/hosts.
 *
 * El shim construye sus propias listas (un bloque malloc por nodo: addrinfo +
 * sockaddr_in contiguos) e intercepta también freeaddrinfo: liberar con la
 * libc una cadena que la libc no armó no está garantizado por POSIX. Las
 * cabezas fabricadas quedan registradas bajo mutex (el proxy resuelve desde
 * hilos concurrentes); si la cabeza es nuestra la liberamos nosotros, si no
 * pasa al freeaddrinfo real.
 *
 * Compilar con: gcc -shared -fPIC -o multiip_shim.so multiip_shim.c -ldl
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static int  (*real_getaddrinfo)(const char *, const char *,
                                const struct addrinfo *, struct addrinfo **);
static void (*real_freeaddrinfo)(struct addrinfo *);
static pthread_once_t resolve_real_once = PTHREAD_ONCE_INIT;

static void
resolve_real(void) {
    real_getaddrinfo  = dlsym(RTLD_NEXT, "getaddrinfo");
    real_freeaddrinfo = dlsym(RTLD_NEXT, "freeaddrinfo");
}

/* registro de cabezas fabricadas por el shim, para que freeaddrinfo sepa
 * de quién es cada lista */
struct owned_head {
    struct addrinfo   *head;
    struct owned_head *next;
};
static struct owned_head *owned = NULL;
static pthread_mutex_t    owned_mutex = PTHREAD_MUTEX_INITIALIZER;

/* nodo propio: un solo bloque con el addrinfo y su sockaddr_in contiguos */
static struct addrinfo *
make_node(const char *ip, unsigned port) {
    struct addrinfo *ai = malloc(sizeof(*ai) + sizeof(struct sockaddr_in));
    if(ai == NULL) {
        return NULL;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)(ai + 1);
    memset(ai,  0, sizeof(*ai));
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &sin->sin_addr);
    ai->ai_family   = AF_INET;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addrlen  = sizeof(*sin);
    ai->ai_addr     = (struct sockaddr *)sin;
    return ai;
}

/* libera una cadena de nodos propios (cada nodo es un único bloque) */
static void
free_own_chain(struct addrinfo *head) {
    while(head != NULL) {
        struct addrinfo *next = head->ai_next;
        free(head);
        head = next;
    }
}

/* arma [ip_a:puerto, ip_b:puerto] y registra la cabeza como propia */
static int
make_pair(const char *ip_a, const char *ip_b, const char *service,
          struct addrinfo **res) {
    const unsigned port = (service != NULL)
                              ? (unsigned)strtoul(service, NULL, 10)
                              : 0;
    struct addrinfo *a = make_node(ip_a, port);
    struct addrinfo *b = make_node(ip_b, port);
    struct owned_head *reg = malloc(sizeof(*reg));
    if(a == NULL || b == NULL || reg == NULL) {
        free(a);
        free(b);
        free(reg);
        return EAI_MEMORY;
    }
    a->ai_next = b;

    reg->head = a;
    pthread_mutex_lock(&owned_mutex);
    reg->next = owned;
    owned     = reg;
    pthread_mutex_unlock(&owned_mutex);

    *res = a;
    return 0;
}

int
getaddrinfo(const char *node, const char *service,
            const struct addrinfo *hints, struct addrinfo **res) {
    pthread_once(&resolve_real_once, resolve_real);
    if(node != NULL && strstr(node, "fallback") != NULL) {
        return make_pair("127.0.0.2", "127.0.0.1", service, res);
    }
    if(node != NULL && strstr(node, "allrefused") != NULL) {
        return make_pair("127.0.0.2", "127.0.0.3", service, res);
    }
    return real_getaddrinfo(node, service, hints, res);
}

void
freeaddrinfo(struct addrinfo *res) {
    pthread_once(&resolve_real_once, resolve_real);
    pthread_mutex_lock(&owned_mutex);
    for(struct owned_head **p = &owned; *p != NULL; p = &(*p)->next) {
        if((*p)->head == res) {
            struct owned_head *found = *p;
            *p = found->next;
            pthread_mutex_unlock(&owned_mutex);
            free(found);
            free_own_chain(res);
            return;
        }
    }
    pthread_mutex_unlock(&owned_mutex);
    real_freeaddrinfo(res);
}

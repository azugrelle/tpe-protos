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

/* resultado scripteado para la llamada n-ésima a un syscall interceptado */
struct call_script {
    int rc;
    int err;   // errno (connect) o SO_ERROR (getsockopt)
};
#define SCRIPT_MAX 4

static int     g_register_calls    = 0;  // intentos de selector_register
static bool    g_register_fail     = false;
static bool    g_setinterest_fail  = false;
static int     g_reply_calls       = 0;  // llamadas a request_reply
static uint8_t g_reply_rep         = 0;  // último REP serializado
// guion de connect(): entrada por llamada; len 0 = passthrough al real. Más
// llamadas que entradas repiten la última (p.ej. "todo conecta" con una sola).
static struct call_script g_connect_script[SCRIPT_MAX];
static int     g_connect_script_len = 0;
static int     g_connect_calls     = 0;
// guion de getsockopt(SO_ERROR): valores a devolver por llamada; len 0 = real
static int     g_soerr_script[SCRIPT_MAX];
static int     g_soerr_script_len  = 0;
static int     g_soerr_calls       = 0;
// freeaddrinfo(): en modo captura no libera (listas artesanales, no liberables)
static bool    g_freeaddrinfo_capture = false;
static int     g_freeaddrinfo_calls   = 0;
static struct addrinfo *g_freeaddrinfo_last = NULL;
static int     g_unregister_calls  = 0;   // fds desregistrados del selector
static int     g_unregister_last_fd = -1;
static int     g_notify_calls      = 0;   // notificaciones de bloqueo
static int     g_notify_fd         = -1;  // fd de la última notificación
static struct blocking_job *g_notify_job = NULL;
static int     g_setinterest_last  = -1;  // último interés pedido al selector
static int     g_pthread_mode      = 0;   // 0 real, 1 falla, 2 éxito sin hilo
static void   *g_pthread_arg       = NULL; // arg capturado en modo 2

// spy de metrics_add_user_site (ACCESS_LOG): state_connect.c la llama en
// connect_fail y en el camino de éxito de connecting; no se linkea metrics.c acá.
static int     g_metrics_calls     = 0;
static bool    g_metrics_success   = false;
static char    g_metrics_username[MAX_USERNAME_LEN];
static char    g_metrics_site[MAX_HOSTNAME_LEN];
static char    g_metrics_port[MAX_PORT_LEN];

static void
reset_injection(void) {
    g_register_calls      = 0;
    g_register_fail       = false;
    g_setinterest_fail    = false;
    g_reply_calls         = 0;
    g_reply_rep           = 0;
    g_connect_script_len  = 0;
    g_connect_calls       = 0;
    g_soerr_script_len    = 0;
    g_soerr_calls         = 0;
    g_freeaddrinfo_capture = false;
    g_freeaddrinfo_calls   = 0;
    g_freeaddrinfo_last    = NULL;
    g_unregister_calls    = 0;
    g_unregister_last_fd  = -1;
    g_notify_calls        = 0;
    g_notify_fd           = -1;
    g_notify_job          = NULL;
    g_setinterest_last    = -1;
    g_pthread_mode        = 0;
    g_pthread_arg         = NULL;
}

/* atajo para el guion más común: connect() exitoso de entrada */
static void
script_connect_ok(void) {
    g_connect_script[0]  = (struct call_script){ .rc = 0, .err = 0 };
    g_connect_script_len = 1;
    g_register_calls     = 0;
    g_register_fail      = false;
    g_setinterest_fail   = false;
    g_reply_calls        = 0;
    g_reply_rep          = 0;
    g_inject             = false;
    g_connect_calls      = 0;
    g_connect_fail_until = 0;
    g_metrics_calls      = 0;
    g_metrics_success    = false;
    g_metrics_username[0] = '\0';
    g_metrics_site[0]     = '\0';
    g_metrics_port[0]     = '\0';
}

void
metrics_add_user_site(const char *username, char *site, char *port, bool success) {
    g_metrics_calls++;
    g_metrics_success = success;
    strncpy(g_metrics_username, username, sizeof(g_metrics_username) - 1);
    strncpy(g_metrics_site, site, sizeof(g_metrics_site) - 1);
    strncpy(g_metrics_port, port, sizeof(g_metrics_port) - 1);
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
    (void)s; (void)fd;
    g_setinterest_last = (int)i;
    return g_setinterest_fail ? SELECTOR_IO : SELECTOR_SUCCESS;
}

selector_status
selector_register(fd_selector s, const int fd, const fd_handler *handler,
                  const fd_interest interest, void *data) {
    (void)s; (void)fd; (void)handler; (void)interest; (void)data;
    g_register_calls++;
    return g_register_fail ? SELECTOR_MAXFD : SELECTOR_SUCCESS;
}

// connect() se intercepta con --wrap: sin guion delega en el real; con guion,
// la llamada n-ésima devuelve el rc/errno de la entrada n (la última entrada
// se repite si hay más llamadas que entradas).
extern int __real_connect(int fd, const struct sockaddr *addr, socklen_t len);

int
__wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if(g_connect_script_len == 0) {
        return __real_connect(fd, addr, len);
    }
    int i = g_connect_calls;
    if(i >= g_connect_script_len) {
        i = g_connect_script_len - 1;
    }
    g_connect_calls++;
    errno = g_connect_script[i].err;
    return g_connect_script[i].rc;
}

// getsockopt() se intercepta con --wrap: sin guion delega en el real; con
// guion, cada consulta de SO_ERROR devuelve el valor scripteado n-ésimo (la
// última entrada se repite). Otras opciones siempre van al real.
extern int __real_getsockopt(int fd, int level, int optname, void *optval,
                             socklen_t *optlen);

int
__wrap_getsockopt(int fd, int level, int optname, void *optval,
                  socklen_t *optlen) {
    if(g_soerr_script_len == 0 || level != SOL_SOCKET || optname != SO_ERROR) {
        return __real_getsockopt(fd, level, optname, optval, optlen);
    }
    int i = g_soerr_calls;
    if(i >= g_soerr_script_len) {
        i = g_soerr_script_len - 1;
    }
    g_soerr_calls++;
    *(int *)optval = g_soerr_script[i];
    return 0;
}

// freeaddrinfo() se intercepta con --wrap: por defecto delega en el real; en
// modo captura solo cuenta y guarda el puntero, sin liberar. Los tests que
// pueden terminar en connect_fail con una lista armada a mano (nodos de stack,
// no liberables) lo necesitan, y de paso asertan "liberada exactamente una vez".
extern void __real_freeaddrinfo(struct addrinfo *res);

void
__wrap_freeaddrinfo(struct addrinfo *res) {
    g_freeaddrinfo_calls++;
    g_freeaddrinfo_last = res;
    if(!g_freeaddrinfo_capture) {
        __real_freeaddrinfo(res);
    }
}

selector_status
selector_unregister_fd(fd_selector s, const int fd) {
    (void)s;
    g_unregister_calls++;
    g_unregister_last_fd = fd;
    return SELECTOR_SUCCESS;
}

// pthread_create se intercepta con --wrap: por defecto delega en el real;
// modo 1 falla (recurso agotado) y modo 2 devuelve éxito capturando el arg
// SIN crear el hilo, para poder correr resolve_thread sincrónicamente.
extern int __real_pthread_create(pthread_t *t, const pthread_attr_t *a,
                                 void *(*f)(void *), void *arg);

int
__wrap_pthread_create(pthread_t *t, const pthread_attr_t *a,
                      void *(*f)(void *), void *arg) {
    switch(g_pthread_mode) {
        case 1:  return EAGAIN;
        case 2:  g_pthread_arg = arg; return 0;
        default: return __real_pthread_create(t, a, f, arg);
    }
}

selector_status
selector_notify_block_job(fd_selector s, const int fd,
                          struct blocking_job *job) {
    (void)s;
    g_notify_calls++;
    g_notify_fd  = fd;
    g_notify_job = job;
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

START_TEST (test_resolve_ipv6_literal) {
    struct socks5 s;
    init_dest(&s, SOCKS5_ATYP_IPV6, "::1", 8080);

    int gai = connect_resolve(&s);

    ck_assert_int_eq(0, gai);
    ck_assert_ptr_nonnull(s.origin_resolution);
    ck_assert_ptr_eq(s.origin_resolution, s.origin_resolution_current);

    struct addrinfo *ai = s.origin_resolution;
    ck_assert_int_eq(AF_INET6,    ai->ai_family);
    ck_assert_int_eq(SOCK_STREAM, ai->ai_socktype);
    ck_assert_int_eq(IPPROTO_TCP, ai->ai_protocol);

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
    ck_assert_int_eq(AF_INET6, sin6->sin6_family);
    ck_assert_uint_eq(htons(8080), sin6->sin6_port);
    struct in6_addr expect = IN6ADDR_LOOPBACK_INIT;
    ck_assert_int_eq(0, memcmp(&expect, &sin6->sin6_addr, sizeof(expect)));

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
    uint8_t  addr[16];
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
    uint8_t  addr[16] = {9, 9, 9, 9};
    uint16_t port = 1234;
    connect_reply_bnd(-1, &atyp, addr, &port);

    ck_assert_uint_eq(SOCKS5_ATYP_IPV4, atyp);
    uint8_t zero[4] = {0, 0, 0, 0};
    ck_assert_int_eq(0, memcmp(addr, zero, 4));
    ck_assert_uint_eq(0, port);
}
END_TEST

START_TEST (test_bnd_from_bound_socket_ipv6) {
    // mismo caso que test_bnd_from_bound_socket pero con un socket IPv6.
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    ck_assert_int_ge(fd, 0);
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_addr   = in6addr_loopback;
    a.sin6_port   = 0;   // puerto efímero
    ck_assert_int_eq(0, bind(fd, (struct sockaddr *)&a, sizeof(a)));
    struct sockaddr_in6 got;
    socklen_t gl = sizeof(got);
    ck_assert_int_eq(0, getsockname(fd, (struct sockaddr *)&got, &gl));

    uint8_t  atyp;
    uint8_t  addr[16];
    uint16_t port;
    connect_reply_bnd(fd, &atyp, addr, &port);

    ck_assert_uint_eq(SOCKS5_ATYP_IPV6, atyp);
    ck_assert_int_eq(0, memcmp(addr, &in6addr_loopback, 16));
    ck_assert_uint_eq(ntohs(got.sin6_port), port);
    close(fd);
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

/* nodo de addrinfo IPv6 (::1) para armar listas de familia mixta */
static void
init_ai6(struct addrinfo *ai, struct sockaddr_in6 *sin6, uint16_t port,
         struct addrinfo *next) {
    memset(sin6, 0, sizeof(*sin6));
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr   = in6addr_loopback;
    sin6->sin6_port   = htons(port);
    memset(ai, 0, sizeof(*ai));
    ai->ai_family   = AF_INET6;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addr     = (struct sockaddr *)sin6;
    ai->ai_addrlen  = sizeof(*sin6);
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
    // 1er candidato falla, 2º conecta
    g_connect_script[0]  = (struct call_script){ .rc = -1, .err = ECONNREFUSED };
    g_connect_script[1]  = (struct call_script){ .rc = 0,  .err = 0 };
    g_connect_script_len = 2;
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

START_TEST (test_connect_try_all_refused_replies_conn_refused) {
    // todos los candidatos rechazan de entrada: se agota la lista, se libera
    // exactamente una vez y el cliente recibe el REP del último error de red.
    struct sockaddr_in a0, a1;
    struct addrinfo    n0, n1;
    init_ai(&n1, &a1, "127.0.0.2", 2222, NULL);
    init_ai(&n0, &a0, "127.0.0.1", 1111, &n1);

    struct socks5 s;
    memset(&s, 0, sizeof(s));
    s.client_fd                 = 100;
    s.origin_fd                 = -1;
    s.references                = 1;
    s.origin_resolution         = &n0;
    s.origin_resolution_current = &n0;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    g_freeaddrinfo_capture = true;
    g_connect_script[0]  = (struct call_script){ .rc = -1, .err = ECONNREFUSED };
    g_connect_script_len = 1;   // se repite: rechazan todos
    unsigned st = connect_try(&key);

    ck_assert_uint_eq(REQUEST_WRITE, st);
    ck_assert_int_eq(2, g_connect_calls);                    // probó los dos
    ck_assert_int_eq(1, g_reply_calls);
    ck_assert_uint_eq(SOCKS5_REP_CONN_REFUSED, g_reply_rep); // 0x05
    ck_assert_int_eq(OP_WRITE, g_setinterest_last);
    ck_assert_int_eq(0, g_register_calls);                   // nadie llegó a activo
    ck_assert_uint_eq(1, s.references);
    ck_assert_int_eq(-1, s.origin_fd);                       // cada intento cerró el suyo
    ck_assert_int_eq(1, g_freeaddrinfo_calls);               // liberada una sola vez
    ck_assert_ptr_eq(&n0, g_freeaddrinfo_last);
    ck_assert_ptr_null(s.origin_resolution);
    ck_assert_ptr_null(s.origin_resolution_current);
}
END_TEST

START_TEST (test_connect_try_network_verdict_beats_local_error) {
    // el 1er candidato tiene un veredicto de red (ECONNREFUSED); el 2º ni
    // siquiera consigue socket (familia bogus). El REP sale del veredicto de
    // red, no del fallo local: 0x05, no 0x01.
    struct sockaddr_in a0, a1;
    struct addrinfo    n0, n1;
    init_ai(&n1, &a1, "127.0.0.2", 2222, NULL);
    init_ai(&n0, &a0, "127.0.0.1", 1111, &n1);
    n1.ai_family = AF_MAX + 1;   // socket() → EAFNOSUPPORT

    struct socks5 s;
    memset(&s, 0, sizeof(s));
    s.client_fd                 = 100;
    s.origin_fd                 = -1;
    s.references                = 1;
    s.origin_resolution         = &n0;
    s.origin_resolution_current = &n0;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    g_freeaddrinfo_capture = true;
    g_connect_script[0]  = (struct call_script){ .rc = -1, .err = ECONNREFUSED };
    g_connect_script_len = 1;
    unsigned st = connect_try(&key);

    ck_assert_uint_eq(REQUEST_WRITE, st);
    ck_assert_int_eq(1, g_connect_calls);                    // el 2º no llegó a connect
    ck_assert_uint_eq(SOCKS5_REP_CONN_REFUSED, g_reply_rep); // red > local
    ck_assert_int_eq(1, g_freeaddrinfo_calls);
    ck_assert_int_eq(-1, s.origin_fd);
}
END_TEST

START_TEST (test_connect_try_last_network_error_wins) {
    // dos veredictos de red distintos: el REP refleja el último observado
    // (ENETUNREACH → ECONNREFUSED ⇒ 0x05, no 0x03).
    struct sockaddr_in a0, a1;
    struct addrinfo    n0, n1;
    init_ai(&n1, &a1, "127.0.0.2", 2222, NULL);
    init_ai(&n0, &a0, "127.0.0.1", 1111, &n1);

    struct socks5 s;
    memset(&s, 0, sizeof(s));
    s.client_fd                 = 100;
    s.origin_fd                 = -1;
    s.references                = 1;
    s.origin_resolution         = &n0;
    s.origin_resolution_current = &n0;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    g_freeaddrinfo_capture = true;
    g_connect_script[0]  = (struct call_script){ .rc = -1, .err = ENETUNREACH };
    g_connect_script[1]  = (struct call_script){ .rc = -1, .err = ECONNREFUSED };
    g_connect_script_len = 2;
    unsigned st = connect_try(&key);

    ck_assert_uint_eq(REQUEST_WRITE, st);
    ck_assert_int_eq(2, g_connect_calls);
    ck_assert_uint_eq(SOCKS5_REP_CONN_REFUSED, g_reply_rep);
    ck_assert_int_eq(1, g_freeaddrinfo_calls);
}
END_TEST

START_TEST (test_connect_try_mixed_family_falls_back_to_ipv4) {
    // el caso real más común de multi-IP con dirección caída: el candidato
    // IPv6 falla (ENETUNREACH, lo que pasa sin conectividad v6) y el IPv4
    // conecta. El socket de cada intento se crea con la familia DEL candidato,
    // no una fija, y origin_addr termina siendo la IPv4.
    struct sockaddr_in6 a0;
    struct sockaddr_in  a1;
    struct addrinfo     n0, n1;
    init_ai(&n1, &a1, "127.0.0.4", 2222, NULL);
    init_ai6(&n0, &a0, 1111, &n1);

    struct socks5 s;
    memset(&s, 0, sizeof(s));
    s.client_fd                 = 100;
    s.origin_fd                 = -1;
    s.references                = 1;
    s.origin_resolution         = &n0;
    s.origin_resolution_current = &n0;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    g_freeaddrinfo_capture = true;
    g_connect_script[0]  = (struct call_script){ .rc = -1, .err = ENETUNREACH };
    g_connect_script[1]  = (struct call_script){ .rc = 0,  .err = 0 };
    g_connect_script_len = 2;
    unsigned st = connect_try(&key);

    ck_assert_uint_eq(CONNECTING, st);
    ck_assert_int_eq(2, g_connect_calls);                // v6 falló, v4 conectó
    ck_assert_int_eq(1, g_register_calls);
    ck_assert_uint_eq(2, s.references);
    ck_assert_int_ne(-1, s.origin_fd);
    ck_assert_int_eq(0, g_reply_calls);                  // nada al cliente todavía
    ck_assert_int_eq(0, g_freeaddrinfo_calls);           // la lista sigue viva
    ck_assert_ptr_eq(&n1, s.origin_resolution_current);

    // origin_addr es la del candidato IPv4 activo, con su largo real
    struct sockaddr_in *copied = (struct sockaddr_in *)&s.origin_addr;
    ck_assert_uint_eq(AF_INET, copied->sin_family);
    ck_assert_uint_eq(inet_addr("127.0.0.4"), copied->sin_addr.s_addr);
    ck_assert_uint_eq(htons(2222), copied->sin_port);
    ck_assert_uint_eq(sizeof(a1), s.origin_addr_len);

    close(s.origin_fd);
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
    script_connect_ok();
    g_register_fail = true;
    unsigned st = connect_try(&key);

    ck_assert_uint_eq(REQUEST_WRITE, st);
    ck_assert_uint_eq(1, s.references);          // nunca se incrementó
    ck_assert_int_eq(1, g_register_calls);       // un intento
    ck_assert_int_eq(-1, s.origin_fd);           // cerrado, sin double-close
    ck_assert_int_eq(1, g_reply_calls);
    ck_assert_uint_eq(SOCKS5_REP_GENERAL_FAILURE, g_reply_rep);
    ck_assert_ptr_null(s.origin_resolution);     // connect_fail liberó la lista

    // connect_fail registró el acceso fallido (ACCESS_LOG)
    ck_assert_int_eq(1, g_metrics_calls);
    ck_assert(!g_metrics_success);
    ck_assert_str_eq("127.0.0.1", g_metrics_site);
    ck_assert_str_eq("1111", g_metrics_port);
}
END_TEST

START_TEST (test_connecting_success_logs_access_and_replies) {
    // connect() no bloqueante ya completó con éxito (SO_ERROR==0): connecting()
    // arma el REPLY de éxito, registra el acceso (ACCESS_LOG) y pasa a
    // REQUEST_WRITE.
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge(lfd, 0);
    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family      = AF_INET;
    la.sin_addr.s_addr = inet_addr("127.0.0.1");
    la.sin_port        = 0;   // puerto efímero
    ck_assert_int_eq(0, bind(lfd, (struct sockaddr *)&la, sizeof(la)));
    ck_assert_int_eq(0, listen(lfd, 1));
    socklen_t ll = sizeof(la);
    ck_assert_int_eq(0, getsockname(lfd, (struct sockaddr *)&la, &ll));

    reset_injection();   // g_inject queda en false: __wrap_connect delega al real

    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge(cfd, 0);
    ck_assert_int_eq(0, connect(cfd, (struct sockaddr *)&la, sizeof(la)));

    struct socks5 s;
    init_dest(&s, SOCKS5_ATYP_IPV4, "example.com", 80);
    strcpy(s.username, "alice");
    s.client_fd = 100;
    s.origin_fd = cfd;

    struct selector_key key = { .s = NULL, .fd = cfd, .data = &s };

    unsigned st = connecting(&key);

    ck_assert_uint_eq(REQUEST_WRITE, st);
    ck_assert_int_eq(1, g_reply_calls);
    ck_assert_uint_eq(SOCKS5_REP_SUCCEEDED, g_reply_rep);

    ck_assert_int_eq(1, g_metrics_calls);
    ck_assert(g_metrics_success);
    ck_assert_str_eq("alice", g_metrics_username);
    ck_assert_str_eq("example.com", g_metrics_site);
    ck_assert_str_eq("80", g_metrics_port);

    close(cfd);
    close(lfd);
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
    script_connect_ok();
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

START_TEST (test_connecting_soerror_retries_next_candidate) {
    // el connect asíncrono del 1er candidato terminó mal (SO_ERROR) y hay otro
    // candidato: connecting cierra y desregistra ese fd, avanza el cursor y
    // reintenta con el siguiente, sin responderle nada al cliente todavía.
    struct sockaddr_in a0, a1;
    struct addrinfo    n0, n1;
    init_ai(&n1, &a1, "127.0.0.2", 2222, NULL);
    init_ai(&n0, &a0, "127.0.0.1", 1111, &n1);

    struct socks5 s;
    memset(&s, 0, sizeof(s));
    s.client_fd                 = 100;
    s.origin_fd                 = socket(AF_INET, SOCK_STREAM, 0);  // real: se cierra
    s.references                = 2;   // client_fd + origin_fd registrados
    s.origin_resolution         = &n0;
    s.origin_resolution_current = &n0;
    ck_assert_int_ne(-1, s.origin_fd);
    const int old_fd = s.origin_fd;

    struct selector_key key = { .s = NULL, .fd = s.origin_fd, .data = &s };

    reset_injection();
    g_freeaddrinfo_capture = true;     // lista a mano: no liberable
    g_soerr_script[0]  = ECONNREFUSED; // veredicto del 1er candidato
    g_soerr_script_len = 1;
    script_connect_ok();               // el connect del 2º es activo de entrada
    unsigned st = connecting(&key);

    ck_assert_uint_eq(CONNECTING, st);
    ck_assert_int_eq(1, g_unregister_calls);             // el fd caído salió del selector
    ck_assert_int_eq(old_fd, g_unregister_last_fd);
    // hay un candidato nuevo en vuelo, registrado una vez (el número de fd
    // puede repetirse: el kernel reusa el slot que liberó el close del 1º)
    ck_assert_int_ne(-1, s.origin_fd);
    ck_assert_int_eq(1, g_register_calls);
    ck_assert_int_eq(0, g_reply_calls);                  // el cliente no vio nada
    ck_assert_int_eq(0, g_freeaddrinfo_calls);           // la lista sigue viva
    ck_assert_ptr_eq(&n1, s.origin_resolution_current);  // cursor avanzó al 2º
    // el error del 1º quedó anotado como último veredicto de red
    ck_assert_int_eq(ECONNREFUSED, s.orig.conn.last_error);
    ck_assert(s.orig.conn.had_connect_error);
    // references: el stub de unregister no corre handle_close (el decremento
    // real pasa ahí), así que acá solo se ve el ++ del nuevo register: 2 → 3.
    ck_assert_uint_eq(3, s.references);
    // origin_addr es la del candidato activo (el 2º)
    struct sockaddr_in *copied = (struct sockaddr_in *)&s.origin_addr;
    ck_assert_uint_eq(inet_addr("127.0.0.2"), copied->sin_addr.s_addr);
    ck_assert_uint_eq(htons(2222), copied->sin_port);

    close(s.origin_fd);   // el fd real del 2º candidato quedó abierto
}
END_TEST

START_TEST (test_connecting_soerror_last_candidate_replies_error) {
    // el connect asíncrono falló y no quedan candidatos: REPLY de error al
    // cliente, lista liberada exactamente una vez y origen limpio.
    struct sockaddr_in a0;
    struct addrinfo    n0;
    init_ai(&n0, &a0, "127.0.0.1", 1111, NULL);

    struct socks5 s;
    memset(&s, 0, sizeof(s));
    s.client_fd                 = 100;
    s.origin_fd                 = socket(AF_INET, SOCK_STREAM, 0);
    s.references                = 2;
    s.origin_resolution         = &n0;
    s.origin_resolution_current = &n0;
    ck_assert_int_ne(-1, s.origin_fd);
    const int old_fd = s.origin_fd;

    struct selector_key key = { .s = NULL, .fd = s.origin_fd, .data = &s };

    reset_injection();
    g_freeaddrinfo_capture = true;
    g_soerr_script[0]  = ETIMEDOUT;
    g_soerr_script_len = 1;
    unsigned st = connecting(&key);

    ck_assert_uint_eq(REQUEST_WRITE, st);
    ck_assert_int_eq(1, g_reply_calls);
    ck_assert_uint_eq(SOCKS5_REP_HOST_UNREACHABLE, g_reply_rep);   // ETIMEDOUT → 0x04
    ck_assert_int_eq(OP_WRITE, g_setinterest_last);                // cliente a escribir
    ck_assert_int_eq(1, g_unregister_calls);
    ck_assert_int_eq(old_fd, g_unregister_last_fd);
    ck_assert_int_eq(-1, s.origin_fd);
    ck_assert_int_eq(1, g_freeaddrinfo_calls);          // liberada exactamente una vez
    ck_assert_ptr_eq(&n0, g_freeaddrinfo_last);         // ...y era la cabeza de la lista
    ck_assert_ptr_null(s.origin_resolution);
    ck_assert_ptr_null(s.origin_resolution_current);
}
END_TEST

START_TEST (test_connecting_success_replies_succeeded) {
    // smoke del flujo completo de éxito: SO_ERROR = 0 ⇒ REPLY 0x00, la lista
    // se libera, el origin_fd queda vivo (y registrado) para el relay.
    struct sockaddr_in a0;
    struct addrinfo    n0;
    init_ai(&n0, &a0, "127.0.0.1", 1111, NULL);

    struct socks5 s;
    memset(&s, 0, sizeof(s));
    s.client_fd                 = 100;
    s.origin_fd                 = socket(AF_INET, SOCK_STREAM, 0);
    s.references                = 2;
    s.origin_resolution         = &n0;
    s.origin_resolution_current = &n0;
    ck_assert_int_ne(-1, s.origin_fd);
    const int old_fd = s.origin_fd;

    struct selector_key key = { .s = NULL, .fd = s.origin_fd, .data = &s };

    reset_injection();
    g_freeaddrinfo_capture = true;
    g_soerr_script[0]  = 0;            // el connect terminó bien
    g_soerr_script_len = 1;
    unsigned st = connecting(&key);

    ck_assert_uint_eq(REQUEST_WRITE, st);
    ck_assert_int_eq(1, g_reply_calls);
    ck_assert_uint_eq(SOCKS5_REP_SUCCEEDED, g_reply_rep);
    ck_assert_int_eq(OP_WRITE, g_setinterest_last);     // cliente a escribir el REPLY
    ck_assert_int_eq(0, g_unregister_calls);            // el origen sigue registrado
    ck_assert_int_eq(old_fd, s.origin_fd);              // ...y es el mismo fd
    ck_assert_int_eq(1, g_freeaddrinfo_calls);          // la lista ya no hace falta
    ck_assert_ptr_null(s.origin_resolution);
    ck_assert_uint_eq(2, s.references);                 // sin cambios

    close(s.origin_fd);
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

START_TEST (test_resolve_done_error_replies_host_unreachable) {
    // la resolución del hilo falló: REPLY 0x04 y el cliente pasa a OP_WRITE
    struct socks5 s;
    init_dest(&s, SOCKS5_ATYP_DOMAIN, "no-resuelve.example", 80);
    s.client_fd   = 100;
    s.origin_fd   = -1;
    s.resolve_gai = EAI_NONAME;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    ck_assert_uint_eq(REQUEST_WRITE, resolve_done(&key));
    ck_assert_int_eq(1, g_reply_calls);
    ck_assert_uint_eq(SOCKS5_REP_HOST_UNREACHABLE, g_reply_rep);
    ck_assert_int_eq(OP_WRITE, g_setinterest_last);
    ck_assert_ptr_null(s.origin_resolution);
    ck_assert_ptr_null(s.origin_resolution_current);
}
END_TEST

START_TEST (test_resolve_done_success_goes_connecting) {
    // resolución exitosa: resolve_done posiciona el cursor y termina en
    // CONNECTING vía connect_try (connect scripteado como activo de entrada).
    struct socks5 s;
    init_dest(&s, SOCKS5_ATYP_IPV4, "127.0.0.1", 1111);
    ck_assert_int_eq(0, connect_resolve(&s));   // lista real (liberable)
    s.client_fd   = 100;
    s.origin_fd   = -1;
    s.references  = 1;
    s.resolve_gai = 0;
    // resolve_done debe reposicionarlo, como queda tras el hilo
    s.origin_resolution_current = NULL;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    script_connect_ok();
    ck_assert_uint_eq(CONNECTING, resolve_done(&key));
    ck_assert_ptr_eq(s.origin_resolution, s.origin_resolution_current);
    ck_assert_uint_eq(2, s.references);
    ck_assert_int_ne(-1, s.origin_fd);

    close(s.origin_fd);
    freeaddrinfo(s.origin_resolution);
}
END_TEST

START_TEST (test_resolve_thread_success_notifies) {
    // el worker corrido sincrónicamente (localhost no sale a la red): deja la
    // lista y el rc, notifica con el job embebido y decrementa el contador.
    struct socks5 s;
    init_dest(&s, SOCKS5_ATYP_DOMAIN, "localhost", 80);
    s.client_fd = 7;

    struct selector_key *key = malloc(sizeof(*key));
    ck_assert_ptr_nonnull(key);
    key->s    = NULL;
    key->fd   = s.client_fd;
    key->data = &s;

    reset_injection();
    // simular el incremento que hace resolve_start antes de crear el hilo
    pthread_mutex_lock(&resolve_mutex);
    resolve_inflight++;
    pthread_mutex_unlock(&resolve_mutex);

    ck_assert_ptr_null(resolve_thread(key));   // libera `key'

    ck_assert_int_eq(0, s.resolve_gai);
    ck_assert_ptr_nonnull(s.origin_resolution);
    ck_assert_int_eq(1, g_notify_calls);
    ck_assert_int_eq(7, g_notify_fd);
    ck_assert_ptr_eq(&s.resolve_job, g_notify_job);
    ck_assert_uint_eq(0, resolve_inflight);

    freeaddrinfo(s.origin_resolution);

    // con el contador en cero la espera de apagado retorna de inmediato
    resolve_shutdown_wait();
}
END_TEST

START_TEST (test_resolve_thread_failure_leaves_no_resolution) {
    // un FQDN irresoluble (.invalid, RFC 6761): rc != 0, no se publica lista
    // (getaddrinfo deja el out-param indefinido en fallo) e igual notifica.
    struct socks5 s;
    init_dest(&s, SOCKS5_ATYP_DOMAIN, "no-existe-x9k2.invalid", 80);
    s.client_fd = 9;

    struct selector_key *key = malloc(sizeof(*key));
    ck_assert_ptr_nonnull(key);
    key->s    = NULL;
    key->fd   = s.client_fd;
    key->data = &s;

    reset_injection();
    pthread_mutex_lock(&resolve_mutex);
    resolve_inflight++;
    pthread_mutex_unlock(&resolve_mutex);

    ck_assert_ptr_null(resolve_thread(key));

    ck_assert_int_ne(0, s.resolve_gai);
    ck_assert_ptr_null(s.origin_resolution);
    ck_assert_int_eq(1, g_notify_calls);
    ck_assert_ptr_eq(&s.resolve_job, g_notify_job);
    ck_assert_uint_eq(0, resolve_inflight);
}
END_TEST

START_TEST (test_resolve_start_pthread_failure_replies_general_failure) {
    // pthread_create falla: REPLY 0x01, sin notificación, contador en cero y
    // la copia del key liberada por resolve_start (valgrind lo confirma).
    struct socks5 s;
    init_dest(&s, SOCKS5_ATYP_DOMAIN, "localhost", 80);
    s.client_fd = 100;
    s.origin_fd = -1;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    g_pthread_mode = 1;
    ck_assert_uint_eq(REQUEST_WRITE, connect_start(&key));
    ck_assert_int_eq(1, g_reply_calls);
    ck_assert_uint_eq(SOCKS5_REP_GENERAL_FAILURE, g_reply_rep);
    ck_assert_int_eq(0, g_notify_calls);
    ck_assert_uint_eq(0, resolve_inflight);
}
END_TEST

START_TEST (test_connect_start_fqdn_goes_resolving) {
    // el camino FQDN de connect_start: cliente a OP_NOOP ANTES de crear el
    // hilo y transición a RESOLVING. El wrap captura el arg sin crear el hilo
    // y el test completa el ciclo corriendo el worker sincrónicamente (si no,
    // quedarían el contador en 1 y la copia del key filtrada).
    struct socks5 s;
    init_dest(&s, SOCKS5_ATYP_DOMAIN, "localhost", 80);
    s.client_fd = 5;
    s.origin_fd = -1;

    struct selector_key key = { .s = NULL, .fd = s.client_fd, .data = &s };

    reset_injection();
    g_pthread_mode = 2;
    ck_assert_uint_eq(RESOLVING, connect_start(&key));
    ck_assert_int_eq(OP_NOOP, g_setinterest_last);
    ck_assert_uint_eq(1, resolve_inflight);
    ck_assert_ptr_nonnull(g_pthread_arg);
    ck_assert_int_eq(0, g_notify_calls);

    ck_assert_ptr_null(resolve_thread(g_pthread_arg));

    ck_assert_uint_eq(0, resolve_inflight);
    ck_assert_int_eq(1, g_notify_calls);
    ck_assert_int_eq(5, g_notify_fd);
    ck_assert_int_eq(0, s.resolve_gai);
    ck_assert_ptr_nonnull(s.origin_resolution);

    freeaddrinfo(s.origin_resolution);
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("state_connect");
    TCase *tc = tcase_create("connect_resolve");

    tcase_add_test(tc, test_resolve_ipv4_literal);
    tcase_add_test(tc, test_resolve_ipv6_literal);
    tcase_add_test(tc, test_resolve_numerichost_rejects_fqdn);
    tcase_add_test(tc, test_bnd_from_bound_socket);
    tcase_add_test(tc, test_bnd_from_bound_socket_ipv6);
    tcase_add_test(tc, test_bnd_degrades_on_bad_fd);
    tcase_add_test(tc, test_connect_retry_second_candidate);
    tcase_add_test(tc, test_connect_try_all_refused_replies_conn_refused);
    tcase_add_test(tc, test_connect_try_network_verdict_beats_local_error);
    tcase_add_test(tc, test_connect_try_last_network_error_wins);
    tcase_add_test(tc, test_connect_try_mixed_family_falls_back_to_ipv4);
    tcase_add_test(tc, test_register_failure_replies_general_failure);
    tcase_add_test(tc, test_setinterest_failure_returns_error);
    tcase_add_test(tc, test_getsockopt_failure_returns_error);
<<<<<<< HEAD
    tcase_add_test(tc, test_connecting_soerror_retries_next_candidate);
    tcase_add_test(tc, test_connecting_soerror_last_candidate_replies_error);
    tcase_add_test(tc, test_connecting_success_replies_succeeded);
=======
    tcase_add_test(tc, test_connecting_success_logs_access_and_replies);
>>>>>>> 3b68131 (access log por usuario)
    tcase_add_test(tc, test_errno_to_rep);
    tcase_add_test(tc, test_gai_error_to_rep);
    tcase_add_test(tc, test_resolve_done_error_replies_host_unreachable);
    tcase_add_test(tc, test_resolve_done_success_goes_connecting);
    tcase_add_test(tc, test_resolve_thread_success_notifies);
    tcase_add_test(tc, test_resolve_thread_failure_leaves_no_resolution);
    tcase_add_test(tc, test_resolve_start_pthread_failure_replies_general_failure);
    tcase_add_test(tc, test_connect_start_fqdn_goes_resolving);
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

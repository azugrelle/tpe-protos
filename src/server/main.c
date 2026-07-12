/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en éste hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#include <time.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>       // getaddrinfo

// #include "include/socks5.h"
#include "selector.h"
#include "config.h"
#include "metrics.h"
#include "include/socks5nio.h"
#include "states/include/state_connect.h"   // resolve_shutdown_wait
#include "include/mgmt.h"
#include "include/args.h"
#include "utils/include/user_auth_utils.h"


/**
 * cota superior, en segundos, del intervalo entre barridos de inactividad.
 * El intervalo efectivo es el mínimo entre esta cota y el `timeout' vigente:
 * con el default de 300s se barre cada 5s, y con un `CONFIG timeout' chico se
 * barre cada `timeout' segundos. Barrer más seguido que el propio timeout no
 * puede cambiar ninguna decisión —su granularidad es de un segundo—, así que
 * es trabajo tirado a la basura.
 */
#define SWEEP_INTERVAL_MAX 5

/**
 * cantidad de señales de terminación recibidas (SIGTERM/SIGINT). La 1ª pide
 * apagado ordenado; la 2ª, corte inmediato. Satura en 2: la lógica solo
 * distingue 0 / 1 / ≥2, e incrementar sin techo ante una ráfaga de señales
 * sería overflow con signo sobre el sig_atomic_t.
 */
static volatile sig_atomic_t sig_count = 0;

static void
sigterm_handler(const int signal) {
    // solo operaciones async-signal-safe acá adentro: nada de I/O.
    (void) signal;
    if(sig_count < 2) {
        sig_count++;
    }
}

/**
 * Resuelve `addr`:`port` (dirección numérica, sin DNS) a un sockaddr_storage
 * apto para bind(2). El mismo código sirve para IPv4 e IPv6: la familia
 * resuelta la decide `addr` (p.ej. "0.0.0.0" da AF_INET, "::1" da AF_INET6).
 * Devuelve la familia resuelta o -1 si `addr` no es una dirección numérica
 * válida en ninguna familia.
 */
static int
resolve_passive(const char *addr, const unsigned short port,
                struct sockaddr_storage *ss, socklen_t *ss_len) {
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%hu", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

    struct addrinfo *res = NULL;
    if(getaddrinfo(addr, port_str, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    memcpy(ss, res->ai_addr, res->ai_addrlen);
    *ss_len = (socklen_t) res->ai_addrlen;
    const int family = res->ai_family;
    freeaddrinfo(res);
    return family;
}

int
main(const int argc, char **argv) {
    struct socks5args args;

    parse_args(argc, argv, &args);

    // contadores volátiles del server (bytes del relay, conexiones, uptime);
    // los alimenta el camino caliente y los lee el monitoreo.
    metrics_init();

    for (int i=0; i < args.nusers; i++) {
        if (!create_user_credentials(args.users[i].name, args.users[i].pass, args.users[i].is_admin)) {
            fprintf(stderr, "invalid user in -u argument: %s\n", args.users[i].name);
            exit(1);
        }
    }

    close(0);

    const char       *err_msg = NULL;
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;
    // declarados (e inicializados) antes del primer goto finally, que los cruza
    int server                = -1;
    int mng_server            = -1;

    struct sockaddr_storage socks_ss;
    socklen_t               socks_ss_len = 0;
    const int socks_family = resolve_passive(args.socks_addr, args.socks_port,
                                              &socks_ss, &socks_ss_len);
    if(socks_family < 0) {
        err_msg = "invalid SOCKS address (-l)";
        goto finally;
    }

    // no-const: el drenado lo cierra y lo blanquea a -1 antes del finally
    server = socket(socks_family, SOCK_STREAM, IPPROTO_TCP);
    if(server < 0) {
        err_msg = "unable to create socket";
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %d\n", args.socks_port);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    if(socks_family == AF_INET6) {
        // explícito: no queremos depender del default del sistema para
        // aceptar clientes v4-mapped por un socket que -l pidió en v6.
        setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int));
    }

    if(bind(server, (struct sockaddr*) &socks_ss, socks_ss_len) < 0) {
        err_msg = "unable to bind socket";
        goto finally;
    }

    if (listen(server, 20) < 0) {
        err_msg = "unable to listen";
        goto finally;
    }

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    // SIGTERM y SIGINT van ambas en sa_mask: sigaction solo bloquea por
    // defecto la señal en curso, y si una interrumpiera al handler de la otra
    // en medio del sig_count++ (read-modify-write, no atómico) se perdería un
    // incremento — justo el que dispara el corte forzado de la 2ª señal.
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    // un peer que cierra su punta a mitad de un send() no debe matar el
    // proceso entero: ignorando SIGPIPE el write falla con EPIPE y cada
    // estado lo maneja localmente (los send() ya usan MSG_NOSIGNAL como
    // segunda línea de defensa).
    signal(SIGPIPE, SIG_IGN);

    // bloquear las señales de terminación en este hilo: el pselect del
    // selector espera con la máscara vacía, así que solo durante la espera
    // quedan desbloqueadas. Una señal que caiga entre el chequeo de sig_count
    // y el arranque del pselect queda pendiente y se entrega apenas empieza
    // la espera (EINTR inmediato) en vez de esperar el timeout del selector.
    // Los hilos de DNS se crean después y heredan la máscara: solo este hilo
    // atiende la terminación.
    sigset_t term_mask;
    sigemptyset(&term_mask);
    sigaddset(&term_mask, SIGTERM);
    sigaddset(&term_mask, SIGINT);
    sigprocmask(SIG_BLOCK, &term_mask, NULL);

    if(selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
    // el pselect retorna a más tardar acá aunque no haya eventos: con el
    // server ocioso, este tick es lo que hace correr el barrido. Alcanza con
    // que iguale la cota del barrido, porque el contrato del timeout es "se
    // cierra tras AL MENOS N segundos de inactividad", no "exactamente a los
    // N": un tick de T solo demora el cierre hasta T segundos. Un CONFIG que
    // baje el timeout tampoco espera al tick — llega por el socket de
    // monitoreo, o sea despierta al pselect con un evento.
    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = SWEEP_INTERVAL_MAX,
            .tv_nsec = 0,
        },
    };
    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }
    const struct fd_handler socksv5 = {
        .handle_read       = socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, server, &socksv5,
                                              OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }

    // socket pasivo del servicio de monitoreo (-L/-P): otro server en el
    // mismo selector, un solo select() atiende proxy + administración.
    struct sockaddr_storage mng_ss;
    socklen_t               mng_ss_len = 0;
    const int mng_family = resolve_passive(args.mng_addr, args.mng_port,
                                            &mng_ss, &mng_ss_len);
    if(mng_family < 0) {
        err_msg = "invalid management address (-L)";
        goto finally;
    }

    mng_server = socket(mng_family, SOCK_STREAM, IPPROTO_TCP);
    if(mng_server < 0) {
        err_msg = "unable to create management socket";
        goto finally;
    }

    fprintf(stdout, "Management listening on TCP port %d\n", args.mng_port);

    setsockopt(mng_server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    if(mng_family == AF_INET6) {
        setsockopt(mng_server, IPPROTO_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int));
    }

    if(bind(mng_server, (struct sockaddr*) &mng_ss, mng_ss_len) < 0) {
        err_msg = "unable to bind management socket";
        goto finally;
    }

    if(listen(mng_server, 20) < 0) {
        err_msg = "unable to listen on management socket";
        goto finally;
    }

    if(selector_fd_set_nio(mng_server) == -1) {
        err_msg = "getting management socket flags";
        goto finally;
    }

    const struct fd_handler mgmtv = {
        .handle_read       = mgmt_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, mng_server, &mgmtv,
                                                  OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering management fd";
        goto finally;
    }

    bool draining = false;
    // momento del último barrido de inactividad. Sin este reloj el barrido
    // correría en CADA vuelta del loop —selector_select retorna ante
    // cualquier evento, no solo al vencer el tick—, recorriendo entera la
    // lista de conexiones vivas miles de veces por segundo bajo carga para
    // redescubrir que ninguna llegó al timeout.
    time_t last_sweep = 0;
    for(;;) {
        // 1ª señal: dejar de aceptar conexiones nuevas (cerrar ambos pasivos)
        // y drenar las activas. Blanquearlos a -1 deja el finally idempotente:
        // sin eso lo cerraría de nuevo, y el número de fd pudo reciclarse.
        if(sig_count > 0 && !draining) {
            draining = true;
            fprintf(stdout, "termination signal: draining active connections\n");
            selector_unregister_fd(selector, server);
            close(server);
            server = -1;
            selector_unregister_fd(selector, mng_server);
            close(mng_server);
            mng_server = -1;
            // las resoluciones que terminen tarde cierran su conexión en vez
            // de avanzar a CONNECTING (escaparían al barrido, que corre una
            // sola vez); después, cerrar lo que esté a medio handshake.
            socksv5_start_draining();
            socksv5_shutdown_handshakes(selector);
        }
        // 2ª señal: corte inmediato, el finally cierra lo que siga vivo.
        // Drenado completo: no queda ninguna conexión SOCKS5 activa.
        if(sig_count >= 2 || (draining && socksv5_live_count() == 0)) {
            break;
        }
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
        // barrido de inactividad: cierra conexiones sin actividad hace más
        // del timeout de la config, y sesiones de monitoreo ociosas (con su
        // propio umbral, ver mgmt.c). Corre también durante el drenado (cerrar
        // ociosas solo ayuda a que el drenado termine antes), pero a lo sumo
        // una vez cada `sweep_interval': así el costo pasa de O(conexiones
        // vivas) por evento a O(conexiones vivas) por intervalo.
        const unsigned timeout = config_get_timeout();
        const time_t sweep_interval = timeout < SWEEP_INTERVAL_MAX
                                    ? (time_t) timeout : SWEEP_INTERVAL_MAX;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if(now.tv_sec - last_sweep >= sweep_interval) {
            last_sweep = now.tv_sec;
            socksv5_sweep_timeouts(selector);
            mgmt_sweep_timeouts(selector);
        }
    }
    // salida por señal: apagado pedido, no un error (exit 0)
    fprintf(stdout, "clean shutdown\n");

    int ret = 0;
finally:
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg,
                                  ss == SELECTOR_IO
                                      ? strerror(errno)
                                      : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    // ningún hilo de resolución puede seguir vivo cuando se destruyan el
    // selector y las conexiones: uno tardío escribiría sobre memoria liberada.
    resolve_shutdown_wait();
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    socksv5_pool_destroy();
    mgmt_pool_destroy();
    metrics_free();
    free_user_credentials();

    if(server >= 0) {
        close(server);
    }
    if(mng_server >= 0) {
        close(mng_server);
    }
    return ret;
}

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

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>   // inet_pton

// #include "include/socks5.h"
#include "../shared/selector.h"
#include "../shared/metrics.h"
#include "include/socks5nio.h"
#include "states/include/state_connect.h"   // resolve_shutdown_wait
#include "include/mgmt.h"
#include "include/args.h"
#include "utils/include/user_auth_utils.h"


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

int
main(const int argc, char **argv) {
    struct socks5args args;

    parse_args(argc, argv, &args);

    // contadores volátiles del server (bytes del relay, conexiones, uptime);
    // los alimenta el camino caliente y los lee el monitoreo.
    metrics_init();

    for (int i=0; i < args.nusers; i++) {
        if (!create_user_credentials(args.users[i].name, args.users[i].pass)) {
            fprintf(stderr, "invalid user in -u argument: %s\n", args.users[i].name);
            exit(1);
        }
    }

    close(0);

    const char       *err_msg = NULL;
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;
    // declarado (e inicializado) antes del primer goto finally, que lo cruza
    int mng_server            = -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(args.socks_port);

    // no-const: el drenado lo cierra y lo blanquea a -1 antes del finally
    int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server < 0) {
        err_msg = "unable to create socket";
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %d\n", args.socks_port);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    if(bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
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
    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
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
    struct sockaddr_in mng_addr;
    memset(&mng_addr, 0, sizeof(mng_addr));
    mng_addr.sin_family = AF_INET;
    mng_addr.sin_port   = htons(args.mng_port);
    if(inet_pton(AF_INET, args.mng_addr, &mng_addr.sin_addr) != 1) {
        err_msg = "invalid management address (-L)";
        goto finally;
    }

    mng_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(mng_server < 0) {
        err_msg = "unable to create management socket";
        goto finally;
    }

    fprintf(stdout, "Management listening on TCP port %d\n", args.mng_port);

    setsockopt(mng_server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    if(bind(mng_server, (struct sockaddr*) &mng_addr, sizeof(mng_addr)) < 0) {
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

    mgmt_init(&args);   // AUTH valida contra args.users[] (flag is_admin)

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

    if(server >= 0) {
        close(server);
    }
    if(mng_server >= 0) {
        close(mng_server);
    }
    return ret;
}

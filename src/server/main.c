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

// #include "socks5.h"
#include "../shared/selector.h"
#include "../shared/metrics.h"
#include "socks5nio.h"
#include "states/include/state_connect.h"   // resolve_shutdown_wait
#include "mgmt.h"
#include "args.h"
#include "utils/include/user_auth_utils.h"


static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int
main(const int argc, char **argv) {
    struct socks5args args;

    parse_args(argc, argv, &args);

    metrics_init();

    for (int i=0; i < args.nusers; i++) {
        if (!create_user_credentials(args.users[i].name, args.users[i].pass)) {
            fprintf(stderr, "invalid user in -u argument: %s\n", args.users[i].name);
            exit(1);
        }
    }

    // contadores volátiles del server (bytes del relay, conexiones, uptime);
    // los alimenta el camino caliente y los lee el monitoreo (T42).
    metrics_init();

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

    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

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

    for(;!done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if(err_msg == NULL) {
        err_msg = "closing";
    }

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

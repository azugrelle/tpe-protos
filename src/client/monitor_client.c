/**
 * monitor_client.c -- cliente de terminal para el servicio de monitoreo del
 * proxy SOCKSv5.
 *
 * A diferencia del server, usa I/O bloqueante: el protocolo de monitoreo es
 * request/response secuencial sobre una única conexión, así que no hay nada
 * que multiplexar y `connect` + `recv`/`send` bloqueantes alcanzan.
 *
 * Códigos de salida: 0 éxito, 1 error de conexión o de protocolo, 2 uso
 * inválido de la línea de comandos.
 */
#include <errno.h>
#include <limits.h>    // LONG_MIN et al
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <netdb.h>         // getaddrinfo
#include <sys/socket.h>
#include <unistd.h>        // close

/** argumentos de línea de comandos ya interpretados */
struct client_args {
    /** dirección y puerto del servicio de monitoreo (el puerto se conserva
     *  como string porque getaddrinfo lo recibe así) */
    const char *mng_addr;
    const char *mng_port;

    /** credenciales de -a, o NULL si no vinieron por línea de comandos */
    const char *admin_user;
    const char *admin_pass;
};

static void
usage(const char *progname, int status) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -a <name>:<pass> Credenciales del administrador del servicio de monitoreo.\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -L <conf  addr>  Dirección donde escucha el servicio de management.\n"
            "   -P <conf port>   Puerto del servicio de management.\n"
            "   -v               Imprime información sobre la versión y termina.\n"
            "\n",
            progname);
    exit(status);
}

static void
version(void) {
    fprintf(stderr, "socks5v monitor client version 0.0\n"
            "ITBA Protocolos de Comunicación 2026/1 -- Grupo X\n"
            "AQUI VA LA LICENCIA\n");
}

/** valida que `s' sea un puerto bien formado; termina con 2 si no lo es */
static const char *
port(const char *s) {
    char *end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX)
    {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        exit(2);
    }
    return s;
}

/** separa el "user:pass" de -a in-place; termina con 2 si está mal formado */
static void
admin_credentials(char *s, struct client_args *args) {
    char *p = strchr(s, ':');
    if (p == NULL) {
        fprintf(stderr, "password not found\n");
        exit(2);
    }
    *p = 0;
    p++;
    args->admin_user = s;
    args->admin_pass = p;
}

static void
parse_client_args(const int argc, char **argv, struct client_args *args) {
    memset(args, 0, sizeof(*args));

    // mismos defaults que el server para su socket de management
    args->mng_addr = "127.0.0.1";
    args->mng_port = "8080";

    int c;
    while ((c = getopt(argc, argv, "a:hL:P:v")) != -1) {
        switch (c) {
        case 'a':
            admin_credentials(optarg, args);
            break;
        case 'h':
            usage(argv[0], 0);
            break;
        case 'L':
            args->mng_addr = optarg;
            break;
        case 'P':
            args->mng_port = port(optarg);
            break;
        case 'v':
            version();
            exit(0);
        default:
            // getopt ya reportó la opción desconocida o el argumento faltante
            usage(argv[0], 2);
        }
    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        usage(argv[0], 2);
    }
}

/**
 * conexión TCP bloqueante al servicio de monitoreo. Resuelve con getaddrinfo
 * (acepta IPv4, IPv6 o nombre) y prueba cada candidato hasta que uno conecte.
 * Retorna el socket conectado, o -1 con el error ya reportado por stderr.
 */
static int
monitor_connect(const char *host, const char *serv) {
    const struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *res, *rp;
    int sock = -1;

    const int err = getaddrinfo(host, serv, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "cannot resolve %s:%s: %s\n", host, serv,
                gai_strerror(err));
        return -1;
    }
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) {
            continue;
        }
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock == -1) {
        fprintf(stderr, "cannot connect to %s:%s\n", host, serv);
    }
    return sock;
}

int
main(const int argc, char **argv) {
    struct client_args args;
    parse_client_args(argc, argv, &args);

    // un send() sobre una conexión que el server ya cerró debe fallar con
    // EPIPE (que se maneja localmente), no matar el proceso
    signal(SIGPIPE, SIG_IGN);

    const int sock = monitor_connect(args.mng_addr, args.mng_port);
    if (sock == -1) {
        return 1;
    }

    // el server saluda apenas acepta la conexión
    char greeting[512];
    const ssize_t n = recv(sock, greeting, sizeof(greeting) - 1, 0);
    if (n <= 0) {
        fprintf(stderr, "server closed the connection\n");
        close(sock);
        return 1;
    }
    greeting[n] = '\0';
    fputs(greeting, stdout);
    fflush(stdout);

    close(sock);
    return 0;
}

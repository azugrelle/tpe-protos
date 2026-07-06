/**
 * monitor_client.c -- cliente de terminal para el servicio de monitoreo del
 * proxy SOCKSv5.
 *
 * A diferencia del server, usa I/O bloqueante: el protocolo de monitoreo es
 * request/response secuencial sobre una única conexión, así que no hay nada
 * que multiplexar y `connect` + `recv`/`send` bloqueantes alcanzan.
 *
 * Las respuestas del server salen por stdout (con flush por respuesta, para
 * que un stdout redirigido sea observable de inmediato); los prompts y los
 * errores van por stderr, así el output capturado por un script queda limpio.
 *
 * Códigos de salida: 0 éxito, 1 error de login/conexión/protocolo, 2 uso
 * inválido de la línea de comandos.
 */
#include <errno.h>
#include <limits.h>    // LONG_MIN et al
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <termios.h>   // eco del password
#include <unistd.h>    // isatty

#include "include/monitor_conn.h"

/** el saludo que fija el protocolo; cualquier otra cosa no es nuestro server */
#define SERVER_GREETING "+OK monitor ready"

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
            "                    Si no se indican, se piden por prompt.\n"
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

///////////////////////////////////////////////////////////////////////////////
// Respuestas

/** muestra una respuesta del server; el flush hace observable un stdout
 *  redirigido sin esperar a que el buffer de stdio se llene */
static void
print_response_line(const char *line) {
    printf("%s\n", line);
    fflush(stdout);
}

static bool
is_ok(const char *line) {
    return strncmp(line, "+OK", 3) == 0
        && (line[3] == '\0' || line[3] == ' ');
}

static bool
is_err(const char *line) {
    return strncmp(line, "-ERR", 4) == 0
        && (line[4] == '\0' || line[4] == ' ');
}

/**
 * valida el saludo inicial contra el contrato exacto del protocolo. Un mero
 * "+OK" aceptaría cualquier server de cualquier protocolo parecido; acá o es
 * nuestro server de monitoreo o no se mandan credenciales.
 */
static bool
check_greeting(struct monitor_conn *conn) {
    const char *line = monitor_conn_recv_line(conn);
    if (line == NULL) {
        return false;
    }
    if (strcmp(line, SERVER_GREETING) != 0) {
        fprintf(stderr, "protocol error: unexpected greeting\n");
        return false;
    }
    print_response_line(line);
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// Login

/**
 * lee una línea de stdin al estilo prompt: el texto va a stderr (stdout es
 * solo para respuestas del server) y el fin de línea se recorta. Con `hide',
 * apaga el eco de la terminal mientras se tipea; si stdin no es una tty no
 * hay eco que apagar y se lee igual (el password nunca se re-imprime).
 * false ante EOF de stdin.
 */
static bool
prompt_line(const char *prompt, char *out, size_t size, bool hide) {
    fprintf(stderr, "%s", prompt);

    struct termios saved;
    bool echo_off = false;
    if (hide && isatty(STDIN_FILENO)) {
        if (tcgetattr(STDIN_FILENO, &saved) == 0) {
            struct termios t = saved;
            t.c_lflag &= ~(tcflag_t)ECHO;
            echo_off = tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) == 0;
        }
    }

    const bool ok = fgets(out, (int)size, stdin) != NULL;

    if (ok && strchr(out, '\n') == NULL) {
        // entrada más larga que el buffer: descartar el resto para que no
        // se derrame sobre el próximo prompt
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) { }
    }
    if (echo_off) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
        fputc('\n', stderr);   // con el eco apagado, el enter no se vio
    }
    if (!ok) {
        return false;
    }
    out[strcspn(out, "\r\n")] = '\0';
    return true;
}

/**
 * autentica al administrador enviando el AUTH que arma el propio cliente.
 * Con credenciales de -a hay un único intento (lo que un script necesita);
 * por prompt se reintenta ante el rechazo del server, pero un EOF de stdin
 * corta sin reintentar (un pipe agotado no debe loopear).
 */
static bool
login(struct monitor_conn *conn, const struct client_args *args) {
    char user_buff[256], pass_buff[256];
    const char *user = args->admin_user;
    const char *pass = args->admin_pass;
    const bool  interactive = (user == NULL);

    for (;;) {
        if (interactive) {
            do {
                if (!prompt_line("user: ", user_buff, sizeof(user_buff),
                                 false)) {
                    fprintf(stderr, "no credentials provided\n");
                    return false;
                }
            } while (user_buff[0] == '\0');   // vacío: volver a preguntar
            if (!prompt_line("password: ", pass_buff, sizeof(pass_buff),
                             true)) {
                fprintf(stderr, "no credentials provided\n");
                return false;
            }
            user = user_buff;
            pass = pass_buff;
        }

        char auth[MONITOR_MAX_LINE];
        if (snprintf(auth, sizeof(auth), "AUTH %s %s", user, pass)
            >= (int)sizeof(auth)) {
            fprintf(stderr, "credentials too long\n");
            return false;
        }
        if (!monitor_conn_send_line(conn, auth)) {
            return false;
        }

        const char *resp = monitor_conn_recv_line(conn);
        if (resp == NULL) {
            return false;
        }
        print_response_line(resp);

        if (is_ok(resp)) {
            return true;
        }
        if (!is_err(resp)) {
            fprintf(stderr, "protocol error: unexpected response\n");
            return false;
        }
        if (!interactive) {
            return false;
        }
        // rechazo con credenciales tipeadas: volver a preguntar
    }
}

int
main(const int argc, char **argv) {
    struct client_args args;
    parse_client_args(argc, argv, &args);

    // un send() sobre una conexión que el server ya cerró debe fallar con
    // EPIPE (que se maneja localmente), no matar el proceso
    signal(SIGPIPE, SIG_IGN);

    struct monitor_conn conn;
    if (!monitor_conn_open(&conn, args.mng_addr, args.mng_port)) {
        return 1;
    }

    int ret = 1;
    if (check_greeting(&conn) && login(&conn, &args)) {
        ret = 0;
    }

    monitor_conn_close(&conn);
    return ret;
}

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
#include <strings.h>   // strcasecmp
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

    /** argumentos posicionales: el comando one-shot; cmd_argc == 0 es REPL */
    char      **cmd_argv;
    int         cmd_argc;
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
            "ITBA Protocolos de Comunicación 2026/1 -- Grupo 22\n"
            "(c) 2026 Grupo 22\n");
}

/** valida que `s' sea un puerto bien formado; termina con 2 si no lo es */
static const char *
port(const char *s) {
    char *end = 0;
    errno = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end
        || errno == ERANGE
        || sl < 1 || sl > USHRT_MAX)
    {
        fprintf(stderr, "port should be in the range 1-65535: %s\n", s);
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
    if (*s == '\0' || *p == '\0') {
        fprintf(stderr, "user and password must not be empty\n");
        exit(2);
    }
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
    // lo posicional es un comando one-shot: se valida contra la tabla de
    // comandos (antes de conectar), no acá
    if (optind < argc) {
        args->cmd_argv = argv + optind;
        args->cmd_argc = argc - optind;
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
 *
 * `verbose' distingue la sesión interactiva (el saludo es feedback) del modo
 * one-shot, donde stdout queda reservado para la respuesta del comando.
 */
static bool
check_greeting(struct monitor_conn *conn, bool verbose) {
    const char *line = monitor_conn_recv_line(conn);
    if (line == NULL) {
        return false;
    }
    if (strcmp(line, SERVER_GREETING) != 0) {
        fprintf(stderr, "protocol error: unexpected greeting\n");
        return false;
    }
    if (verbose) {
        print_response_line(line);
    }
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
 *
 * Sin `verbose' (one-shot) el resultado del AUTH no pasa por stdout: el
 * éxito es silencioso y el rechazo se reporta por stderr.
 */
static bool
login(struct monitor_conn *conn, const struct client_args *args,
      bool verbose) {
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
        if (verbose) {
            print_response_line(resp);
        }

        if (is_ok(resp)) {
            return true;
        }
        if (!is_err(resp)) {
            fprintf(stderr, "protocol error: unexpected response\n");
            return false;
        }
        if (!verbose) {
            fprintf(stderr, "%s\n", resp);   // el rechazo, al canal de errores
        }
        if (!interactive) {
            return false;
        }
        // rechazo con credenciales tipeadas: volver a preguntar
    }
}

///////////////////////////////////////////////////////////////////////////////
// Tabla de comandos
//
// El cliente solo envía comandos que conoce: lo que no matchea la tabla se
// rechaza acá, sin tocar el socket. Eso garantiza que siempre se sabe qué
// framing esperar de la respuesta, y que nunca viaja una línea inválida.

/** framing de la respuesta exitosa, fijado por comando (es una invariante
 *  del protocolo, no una heurística: ver src/docs/monitoring_protocol.md) */
enum resp_kind {
    RESP_SINGLE,   /**< una sola línea: `+OK ...' */
    RESP_MULTI,    /**< `+OK' + cuerpo + `.': se acumula entera y luego se
                        muestra, para poder formatearla como un todo */
    RESP_STREAM,   /**< `+OK' + cuerpo + `.': se muestra según llega. Para
                        listas sin cota conocida (el registro de accesos),
                        donde acumular no tiene un tope defendible */
};

struct response;

struct client_cmd {
    const char    *name;      /**< como lo tipea el usuario */
    const char    *proto;     /**< como viaja al server */
    int            min_args;
    int            max_args;
    /** true si el último argumento es el resto de la línea, crudo (permite
     *  passwords y valores con espacios, igual que el protocolo) */
    bool           raw_tail;
    enum resp_kind kind;
    /** decorador de la respuesta acumulada (solo RESP_MULTI); NULL = cruda */
    void         (*format)(const struct response *resp);
    const char    *usage;
    const char    *descr;
};

static void format_key_values(const struct response *resp);
static void format_users(const struct response *resp);

static const struct client_cmd client_commands[] = {
    { "stats",       "STATS",       0, 0, false, RESP_MULTI,  format_key_values,
      "stats",                   "métricas globales del proxy" },
    { "users",       "USERS",       0, 0, false, RESP_MULTI,  format_users,
      "users",                   "usuarios conectados en este momento" },
    { "connections", "CONNECTIONS", 0, 0, false, RESP_MULTI,  format_key_values,
      "connections",             "conteos de conexiones del proxy" },
    { "config",      "CONFIG",      2, 2, true,  RESP_SINGLE, NULL,
      "config <param> <valor>",  "ajusta un parámetro en runtime (timeout, buf_size)" },
    { "add-user",    "ADD_USER",    2, 2, true,  RESP_SINGLE, NULL,
      "add-user <user> <pass>",  "alta de un usuario del proxy" },
    { "del-user",    "DEL_USER",    1, 1, false, RESP_SINGLE, NULL,
      "del-user <user>",         "baja de un usuario del proxy" },
    { "access-log",  "ACCESS_LOG",  0, 1, false, RESP_STREAM, NULL,
      "access-log [user]",       "registro de accesos, de todos o de un usuario" },
    { "quit",        "QUIT",        0, 0, false, RESP_SINGLE, NULL,
      "quit",                    "cierra la sesión" },
};

/** busca por nombre amigable o de protocolo, sin distinguir mayúsculas */
static const struct client_cmd *
find_command(const char *name) {
    for (unsigned i = 0; i < sizeof(client_commands)/sizeof(client_commands[0]); i++) {
        if (strcasecmp(client_commands[i].name, name) == 0
         || strcasecmp(client_commands[i].proto, name) == 0) {
            return &client_commands[i];
        }
    }
    return NULL;
}

static void
print_help(void) {
    fprintf(stderr, "comandos:\n");
    for (unsigned i = 0; i < sizeof(client_commands)/sizeof(client_commands[0]); i++) {
        fprintf(stderr, "  %-24s %s\n",
                client_commands[i].usage, client_commands[i].descr);
    }
    fprintf(stderr, "  %-24s %s\n", "help", "muestra esta ayuda");
}

/** true si `s' es NULL o solo espacios */
static bool
blank(const char *s) {
    if (s == NULL) {
        return true;
    }
    while (*s == ' ') {
        s++;
    }
    return *s == '\0';
}

/**
 * valida los argumentos contra la aridad del comando y arma la línea de
 * protocolo. `rest' es lo que siguió al comando, crudo (NULL si no hubo
 * espacio). false ante argumentos inválidos, con el uso ya impreso: es un
 * error local, no viajó nada al server.
 */
static bool
build_protocol_line(const struct client_cmd *cmd, const char *rest,
                    char out[MONITOR_MAX_LINE]) {
    int n = -1;

    if (cmd->max_args == 0) {
        // los espacios de más no son "argumentos"; contenido sí
        if (!blank(rest)) {
            goto bad_args;
        }
        n = snprintf(out, MONITOR_MAX_LINE, "%s", cmd->proto);
    } else if (cmd->raw_tail) {
        // <token> <resto crudo>: el mismo split que hace el server, así que
        // reenviar `rest' tal cual preserva el crudo (espacios incluidos)
        const char *sp = (rest == NULL) ? NULL : strchr(rest, ' ');
        if (rest == NULL || rest[0] == ' ' || sp == NULL || sp[1] == '\0') {
            goto bad_args;
        }
        n = snprintf(out, MONITOR_MAX_LINE, "%s %s", cmd->proto, rest);
    } else {
        // cero o un token, sin cola cruda
        if (blank(rest)) {
            if (cmd->min_args > 0) {
                goto bad_args;
            }
            n = snprintf(out, MONITOR_MAX_LINE, "%s", cmd->proto);
        } else {
            if (rest[0] == ' ') {   // primer token vacío ("del-user  x")
                goto bad_args;
            }
            const char *end = strchr(rest, ' ');
            if (end != NULL && !blank(end)) {   // sobra un segundo token
                goto bad_args;
            }
            const int toklen = (end == NULL) ? (int)strlen(rest)
                                             : (int)(end - rest);
            n = snprintf(out, MONITOR_MAX_LINE, "%s %.*s",
                         cmd->proto, toklen, rest);
        }
    }

    if (n < 0 || n >= MONITOR_MAX_LINE) {
        fprintf(stderr, "line too long\n");
        return false;
    }
    return true;

bad_args:
    fprintf(stderr, "invalid arguments -- usage: %s\n", cmd->usage);
    return false;
}

///////////////////////////////////////////////////////////////////////////////
// Respuestas multilínea acumuladas
//
// Se junta la respuesta entera antes de mostrarla: así el formateo puede
// tratarla como un todo (encabezados con conteo, columnas alineadas). El tope
// es holgado a propósito: el server garantiza respuestas acotadas y chicas
// para todos los comandos que se acumulan; excederlo no es una respuesta
// grande, es un server que no habla este protocolo.

#define RESPONSE_MAX_LINES 128
#define RESPONSE_MAX_BYTES (16 * 1024)

struct response {
    const char *lines[RESPONSE_MAX_LINES];
    size_t      nlines;
    char        data[RESPONSE_MAX_BYTES];
    size_t      used;
};

/** copia `line' adentro de la respuesta; false si no entra */
static bool
response_append(struct response *resp, const char *line) {
    const size_t len = strlen(line) + 1;

    if (resp->nlines == RESPONSE_MAX_LINES
     || len > RESPONSE_MAX_BYTES - resp->used) {
        return false;
    }
    memcpy(resp->data + resp->used, line, len);
    resp->lines[resp->nlines++] = resp->data + resp->used;
    resp->used += len;
    return true;
}

/** muestra la respuesta tal cual llegó, framing incluido */
static void
print_response_raw(const struct response *resp) {
    printf("+OK\n");
    for (size_t i = 0; i < resp->nlines; i++) {
        printf("%s\n", resp->lines[i]);
    }
    printf(".\n");
    fflush(stdout);
}

///////////////////////////////////////////////////////////////////////////////
// Decoradores de formato
//
// Embellecer sin ocultar: los valores que se transforman llevan el crudo
// entre paréntesis cuando la forma humana pierde precisión, y todo lo que no
// se reconoce (claves nuevas, líneas que no son `clave: valor') pasa tal
// cual — un server con métricas más nuevas no se esconde ni rompe nada.

/** ancho de la columna de claves (la más larga hoy ocupa 23 con su ':') */
#define KEY_COLUMN 24

/** peor caso de decorate_value(): 47 human + " (" + 20 uint64 + ")" + NUL */
#define PRETTY_VALUE_MAX 96

static void
format_duration(unsigned long long secs, char *out, size_t size) {
    const unsigned long long d = secs / 86400;
    const unsigned h = (unsigned)((secs / 3600) % 24);
    const unsigned m = (unsigned)((secs / 60) % 60);
    const unsigned s = (unsigned)(secs % 60);

    if (d > 0) {
        snprintf(out, size, "%llud %uh %um %us", d, h, m, s);
    } else if (h > 0) {
        snprintf(out, size, "%uh %um %us", h, m, s);
    } else {
        snprintf(out, size, "%um %us", m, s);
    }
}

static void
format_bytes(unsigned long long bytes, char *out, size_t size) {
    static const char *units[] = { "KB", "MB", "GB", "TB" };
    double   v = (double)bytes;
    unsigned u = 0;

    v /= 1024;
    while (v >= 1024 && u < sizeof(units)/sizeof(units[0]) - 1) {
        v /= 1024;
        u++;
    }
    snprintf(out, size, "%.1f %s", v, units[u]);
}

static bool
key_is(const char *key, size_t keylen, const char *name) {
    return strlen(name) == keylen && strncmp(key, name, keylen) == 0;
}

/**
 * devuelve la forma humana del valor de una clave conocida (armada en `out'),
 * o `value' intacto si la clave no se reconoce, el valor no es un número
 * limpio, o la forma humana no aporta (segundos < 1m, bytes < 1K).
 */
static const char *
decorate_value(const char *key, size_t keylen, const char *value,
               char *out, size_t size) {
    char *end;
    errno = 0;
    const unsigned long long v = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return value;
    }

    char human[48];
    if (key_is(key, keylen, "uptime") && v >= 60) {
        format_duration(v, human, sizeof(human));
        snprintf(out, size, "%s (%llu)", human, v);
        return out;
    }
    if (key_is(key, keylen, "bytes_transferred") && v >= 1024) {
        format_bytes(v, human, sizeof(human));
        snprintf(out, size, "%s (%llu)", human, v);
        return out;
    }
    return value;
}

/** respuestas `clave: valor' (stats, connections): columnas alineadas y
 *  valores conocidos en forma humana */
static void
format_key_values(const struct response *resp) {
    for (size_t i = 0; i < resp->nlines; i++) {
        const char *line = resp->lines[i];
        const char *sep  = strstr(line, ": ");

        if (sep == NULL || sep == line) {
            printf("%s\n", line);   // no es `clave: valor': pasa tal cual
            continue;
        }
        const size_t keylen = (size_t)(sep - line);
        const char  *value  = sep + 2;

        char key[256];
        if (keylen + 2 > sizeof(key)) {   // clave absurda: antes que truncarla
            printf("%s\n", line);         // (= ocultar datos), pasa tal cual
            continue;
        }
        snprintf(key, sizeof(key), "%.*s:", (int)keylen, line);

        char pretty[PRETTY_VALUE_MAX];
        printf("%-*s %s\n", KEY_COLUMN, key,
               decorate_value(line, keylen, value, pretty, sizeof(pretty)));
    }
    fflush(stdout);
}

/** lista de usuarios activos: encabezado con conteo y nombres indentados */
static void
format_users(const struct response *resp) {
    printf("active users (%zu):\n", resp->nlines);
    if (resp->nlines == 0) {
        printf("  (none)\n");
    }
    for (size_t i = 0; i < resp->nlines; i++) {
        printf("  %s\n", resp->lines[i]);
    }
    fflush(stdout);
}

///////////////////////////////////////////////////////////////////////////////
// Ejecución de comandos

/**
 * envía la línea ya armada y consume la respuesta completa según el framing
 * del comando. Deja en *server_ok si el server respondió `+OK'.
 * false solo ante errores fatales para la sesión (conexión o protocolo), ya
 * reportados; un `-ERR' del server es una respuesta válida y la sesión sigue.
 */
static bool
run_command(struct monitor_conn *conn, const struct client_cmd *cmd,
            const char *line, bool *server_ok) {
    *server_ok = false;

    if (!monitor_conn_send_line(conn, line)) {
        return false;
    }
    const char *first = monitor_conn_recv_line(conn);
    if (first == NULL) {
        return false;
    }

    if (is_err(first)) {
        // los errores son siempre de una sola línea, sea cual sea el comando
        print_response_line(first);
        return true;
    }
    if (!is_ok(first)) {
        fprintf(stderr, "protocol error: unexpected response\n");
        return false;
    }
    *server_ok = true;

    if (cmd->kind == RESP_SINGLE) {
        print_response_line(first);
        return true;
    }

    // multilínea: la invariante del protocolo exige el `+OK' pelado; un
    // `+OK <mensaje>' acá significaría esperar un cuerpo que nunca llega
    if (strcmp(first, "+OK") != 0) {
        fprintf(stderr, "protocol error: unexpected response\n");
        return false;
    }

    if (cmd->kind == RESP_STREAM) {
        print_response_line(first);
        for (;;) {
            const char *l = monitor_conn_recv_line(conn);
            if (l == NULL) {
                return false;
            }
            print_response_line(l);
            if (strcmp(l, ".") == 0) {
                return true;
            }
        }
    }

    struct response resp = { .nlines = 0, .used = 0 };
    for (;;) {
        const char *l = monitor_conn_recv_line(conn);
        if (l == NULL) {
            return false;
        }
        if (strcmp(l, ".") == 0) {
            break;
        }
        if (!response_append(&resp, l)) {
            fprintf(stderr, "protocol error: response too large\n");
            return false;
        }
    }
    if (cmd->format != NULL) {
        cmd->format(&resp);
    } else {
        print_response_raw(&resp);
    }
    return true;
}

/** despedida limpia: QUIT, esperar el bye y cerrar */
static bool
quit_session(struct monitor_conn *conn) {
    bool ok;
    if (!run_command(conn, find_command("quit"), "QUIT", &ok)) {
        return false;
    }
    return ok;
}

///////////////////////////////////////////////////////////////////////////////
// Loop de comandos

/** true si la sesión terminó bien (quit/Ctrl-D con su bye); false ante un
 *  error fatal de conexión o protocolo, ya reportado */
static bool
repl(struct monitor_conn *conn) {
    char input[1024];

    for (;;) {
        fprintf(stderr, "monitor> ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            // fin de la entrada (Ctrl-D o pipe agotado): despedida limpia
            fputc('\n', stderr);
            return quit_session(conn);
        }
        if (strchr(input, '\n') == NULL && !feof(stdin)) {
            // descartar el resto de una línea que no entró en el buffer
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) { }
            fprintf(stderr, "line too long\n");
            continue;
        }
        input[strcspn(input, "\r\n")] = '\0';

        char *p = input;
        while (*p == ' ' || *p == '\t') {   // trim izquierdo, solo acá:
            p++;                            // los argumentos van crudos
        }
        if (*p == '\0') {
            continue;                       // línea vacía: nuevo prompt
        }

        char *rest = strchr(p, ' ');
        if (rest != NULL) {
            *rest++ = '\0';
        }

        if (strcasecmp(p, "help") == 0) {
            print_help();
            continue;
        }
        const struct client_cmd *cmd = find_command(p);
        if (cmd == NULL) {
            fprintf(stderr, "unknown command '%s', try 'help'\n", p);
            continue;
        }

        char line[MONITOR_MAX_LINE];
        if (!build_protocol_line(cmd, rest, line)) {
            continue;   // error local ya reportado; la sesión sigue
        }

        bool server_ok;
        if (!run_command(conn, cmd, line, &server_ok)) {
            return false;
        }
        if (server_ok && strcmp(cmd->proto, "QUIT") == 0) {
            return true;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Modo one-shot

/**
 * re-arma los argumentos posicionales con un espacio simple entre cada uno.
 * El contenido de cada argumento se preserva (las comillas del shell ya
 * hicieron su parte); el espaciado original entre ellos, no — el shell lo
 * consumió antes de que llegara acá. false si no entra en `out'.
 */
static bool
join_args(char **argv, int argc, char *out, size_t size) {
    size_t used = 0;

    for (int i = 0; i < argc; i++) {
        const size_t len = strlen(argv[i]);
        if (used + (i > 0 ? 1 : 0) + len + 1 > size) {
            return false;
        }
        if (i > 0) {
            out[used++] = ' ';
        }
        memcpy(out + used, argv[i], len);
        used += len;
    }
    out[used] = '\0';
    return true;
}

/**
 * despedida del one-shot: cerrar sin QUIT sería descortés con el protocolo,
 * pero su `+OK bye' no es parte de la respuesta pedida, así que no toca
 * stdout ni cambia el exit code — la respuesta que importaba ya llegó.
 */
static void
quit_farewell(struct monitor_conn *conn) {
    if (monitor_conn_send_line(conn, "QUIT")) {
        (void)monitor_conn_recv_line(conn);
    }
}

int
main(const int argc, char **argv) {
    struct client_args args;
    parse_client_args(argc, argv, &args);

    // un send() sobre una conexión que el server ya cerró debe fallar con
    // EPIPE (que se maneja localmente), no matar el proceso
    signal(SIGPIPE, SIG_IGN);

    const bool oneshot = args.cmd_argc > 0;

    // la validación local del comando one-shot corre ANTES de conectar: un
    // error de uso no toca la red y sale con 2, como los errores de CLI
    const struct client_cmd *cmd = NULL;
    char line[MONITOR_MAX_LINE];
    if (oneshot) {
        if (strcasecmp(args.cmd_argv[0], "help") == 0) {
            print_help();
            return 0;
        }
        cmd = find_command(args.cmd_argv[0]);
        if (cmd == NULL) {
            fprintf(stderr, "unknown command '%s', try 'help'\n",
                    args.cmd_argv[0]);
            return 2;
        }
        char rest[1024];
        if (!join_args(args.cmd_argv + 1, args.cmd_argc - 1,
                       rest, sizeof(rest))) {
            fprintf(stderr, "line too long\n");
            return 2;
        }
        if (!build_protocol_line(cmd, args.cmd_argc > 1 ? rest : NULL,
                                 line)) {
            return 2;
        }
    }

    struct monitor_conn conn;
    if (!monitor_conn_open(&conn, args.mng_addr, args.mng_port)) {
        return 1;
    }

    int ret = 1;
    if (check_greeting(&conn, !oneshot) && login(&conn, &args, !oneshot)) {
        if (oneshot) {
            bool server_ok;
            if (run_command(&conn, cmd, line, &server_ok)) {
                ret = server_ok ? 0 : 1;
                if (strcmp(cmd->proto, "QUIT") != 0) {
                    // si el comando pedido ya era quit, ese fue EL QUIT
                    quit_farewell(&conn);
                }
            }
        } else {
            ret = repl(&conn) ? 0 : 1;
        }
    }

    monitor_conn_close(&conn);
    return ret;
}

/**
 * monitor_conn.c -- transporte del cliente de monitoreo.
 *
 * I/O bloqueante a propósito: el protocolo es request/response secuencial y
 * no hay nada que multiplexar. La única concesión es un SO_RCVTIMEO generoso
 * como red contra un server vivo pero mudo (una respuesta a la que nunca le
 * llega el terminador): sin él, ese caso colgaría al cliente para siempre.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <netdb.h>         // getaddrinfo
#include <sys/socket.h>
#include <sys/time.h>      // struct timeval
#include <unistd.h>        // close

#include "include/monitor_conn.h"

/** cuánto esperar una respuesta antes de dar la sesión por muerta */
#define RESPONSE_TIMEOUT_SECONDS 30

bool
monitor_conn_open(struct monitor_conn *conn, const char *host,
                  const char *serv) {
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
        return false;
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
        return false;
    }

    // el timeout solo corre mientras se espera una respuesta (recv), no
    // mientras el usuario piensa; si el setsockopt falla se sigue sin la
    // red de seguridad, no es motivo para negar la conexión
    const struct timeval timeout = { .tv_sec = RESPONSE_TIMEOUT_SECONDS };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    memset(conn, 0, sizeof(*conn));
    conn->fd = sock;
    return true;
}

bool
monitor_conn_send_line(struct monitor_conn *conn, const char *line) {
    const size_t len = strlen(line);

    // contando el '\n' que agrega esta función; el server además cierra la
    // conexión ante una línea que exceda el máximo, así que mandarla igual
    // solo cambiaría el mensaje de error por uno peor
    if (len + 1 > MONITOR_MAX_LINE) {
        fprintf(stderr, "line too long\n");
        return false;
    }

    char out[MONITOR_MAX_LINE];
    memcpy(out, line, len);
    out[len] = '\n';

    size_t sent = 0;
    while (sent < len + 1) {
        const ssize_t n = send(conn->fd, out + sent, len + 1 - sent,
                               MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EPIPE || errno == ECONNRESET) {
                fprintf(stderr, "server closed the connection\n");
            } else {
                perror("send");
            }
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

const char *
monitor_conn_recv_line(struct monitor_conn *conn) {
    for (;;) {
        // ¿ya hay una línea completa entre los bytes recibidos?
        char *nl = memchr(conn->buff + conn->start, '\n',
                          conn->len - conn->start);
        if (nl != NULL) {
            char *line = conn->buff + conn->start;
            conn->start = (size_t)(nl - conn->buff) + 1;
            *nl = '\0';
            if (nl > line && nl[-1] == '\r') {
                nl[-1] = '\0';   // tolerar servers que terminan en \r\n
            }
            return line;
        }

        // no: compactar lo consumido y traer más bytes
        if (conn->start > 0) {
            memmove(conn->buff, conn->buff + conn->start,
                    conn->len - conn->start);
            conn->len -= conn->start;
            conn->start = 0;
        }
        if (conn->len == sizeof(conn->buff)) {
            fprintf(stderr, "protocol error: response line too long\n");
            return NULL;
        }

        const ssize_t n = recv(conn->fd, conn->buff + conn->len,
                               sizeof(conn->buff) - conn->len, 0);
        if (n == 0) {
            if (conn->len > 0) {
                // el server cerró dejando una línea a medias: eso nunca es
                // un cierre legítimo del protocolo
                fprintf(stderr, "protocol error: connection closed mid-line\n");
            } else {
                fprintf(stderr, "server closed the connection\n");
            }
            return NULL;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "timed out waiting for response\n");
            } else {
                perror("recv");
            }
            return NULL;
        }
        conn->len += (size_t)n;
    }
}

void
monitor_conn_close(struct monitor_conn *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1;
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>

#include "../shared/selector.h"
#include "../shared/buffer.h"

#define PORT        8080
#define BUFFER_SIZE 1024

// Estado por cliente: su fd y el buffer con los datos pendientes de echear
typedef struct {
    int     fd;
    buffer  buf;
    uint8_t raw[BUFFER_SIZE];
} client_data;

// ─── handlers del cliente ────────────────────────────────────────────────────

static void
client_read(struct selector_key *key) {
    client_data *c = key->data;

    size_t   space;
    uint8_t *ptr = buffer_write_ptr(&c->buf, &space);
    ssize_t  n   = recv(key->fd, ptr, space, 0);

    if (n <= 0) {
        // n==0: cliente cerró; n<0: error de red
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    buffer_write_adv(&c->buf, n);
    // Tenemos datos para escribir: solo nos interesa OP_WRITE hasta vaciar el buffer
    selector_set_interest_key(key, OP_WRITE);
}

static void
client_write(struct selector_key *key) {
    client_data *c = key->data;

    size_t   count;
    uint8_t *ptr = buffer_read_ptr(&c->buf, &count);
    ssize_t  n   = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n < 0) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    buffer_read_adv(&c->buf, n);

    if (!buffer_can_read(&c->buf)) {
        // Buffer vaciado: volvemos a escuchar al cliente
        selector_set_interest_key(key, OP_READ);
    }
}

static void
client_close(struct selector_key *key) {
    client_data *c = key->data;
    printf("fd=%d desconectado\n", c->fd);
    close(c->fd);
    free(c);
}

static const fd_handler client_handler = {
    .handle_read  = client_read,
    .handle_write = client_write,
    .handle_block = NULL,
    .handle_close = client_close,
};

// ─── handler del server (solo acepta conexiones) ─────────────────────────────

static void
server_accept(struct selector_key *key) {
    struct sockaddr_in addr;
    socklen_t          len = sizeof(addr);

    int client_fd = accept(key->fd, (struct sockaddr *)&addr, &len);
    if (client_fd < 0) {
        perror("accept");
        return;
    }

    selector_fd_set_nio(client_fd);

    client_data *c = malloc(sizeof(*c));
    if (c == NULL) {
        close(client_fd);
        return;
    }
    c->fd = client_fd;
    buffer_init(&c->buf, BUFFER_SIZE, c->raw);

    if (selector_register(key->s, client_fd, &client_handler, OP_READ, c) != SELECTOR_SUCCESS) {
        free(c);
        close(client_fd);
        return;
    }

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    printf("Nueva conexión: %s:%d (fd=%d)\n", ip, ntohs(addr.sin_port), client_fd);
}

static const fd_handler server_handler = {
    .handle_read  = server_accept,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = NULL,
};

// ─── main ────────────────────────────────────────────────────────────────────

int main(void) {
    signal(SIGPIPE, SIG_IGN);  // send() falla con EPIPE en vez de matar el proceso

    // 1. Inicializar la librería del selector
    const struct selector_init conf = {
        .signal         = SIGUSR1,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 },
    };
    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_init falló\n");
        return 1;
    }

    // 2. Crear el socket servidor
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    selector_fd_set_nio(server_fd);

    struct sockaddr_in server_addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(PORT),
    };
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("Non-blocking echo server listening on port %d\n", PORT);


    // 3. Crear el selector y registrar el server fd
    fd_selector sel = selector_new(10);
    if (sel == NULL) {
        fprintf(stderr, "selector_new falló\n");
        return 1;
    }
    if (selector_register(sel, server_fd, &server_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        fprintf(stderr, "selector_register falló\n");
        return 1;
    }

    printf("Echo server escuchando en puerto %d\n", PORT);

    // 4. Loop de eventos — se bloquea en pselect() hasta que hay actividad real
    selector_status st;
    do {
        st = selector_select(sel);
    } while (st == SELECTOR_SUCCESS);

    fprintf(stderr, "Error en selector: %s\n", selector_error(st));

    selector_destroy(sel);
    selector_close();
    close(server_fd);
    return 0;
}

#include "metrics.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Estado global de métricas. Único, sin locks: todo el camino caliente corre en
 * el hilo del selector (ver metrics.h). El hilo de DNS (T50) no debe tocarlo.
 */

static uint64_t total_connections = 0;
static uint64_t current_connections = 0;
static uint64_t max_concurrent_connections = 0;
static uint64_t total_bytes_transferred = 0;
static time_t   server_start_time = 0;

/*
 * Modelo de usuarios:
 *  - all_time_users: fuente de verdad. Un entry por usuario distinto visto desde
 *    el arranque. Es DUEÑO de sites_visited (alimenta ACCESS_LOG).
 *  - active_users: subconjunto conectado ahora. Copia superficial de
 *    username/last_seen; NO es dueño de sites (evita doble free). Un entry por
 *    usuario distinto: N conexiones del mismo usuario comparten el entry, y
 *    active_conns (paralelo por índice) cuenta cuántas siguen vivas — el entry
 *    se da de baja recién cuando muere la última, no en la primera desconexión.
 */
static user_info active_users[MAX_CONNECTIONS];
static int active_conns[MAX_CONNECTIONS];
static int active_count = 0;

static user_info *all_time_users = NULL;
static int all_time_count = 0;
static int all_time_capacity = 0;

#define GROW_STEP 10

/* Copia una cadena a memoria propia (evita depender de strdup con -pedantic). */
static char *
dup_str(const char *s) {
    if (s == NULL) {
        return NULL;
    }
    size_t len = strlen(s) + 1;
    char *copy = malloc(len);
    if (copy != NULL) {
        memcpy(copy, s, len);
    }
    return copy;
}

/*
 * Reemplaza por '?' todo byte fuera del ASCII imprimible sin espacio. Las
 * respuestas del monitoreo separan campos con espacio y registros con líneas
 * (y un "." solo en su línea termina las listas), así que un valor con
 * espacios o caracteres de control rompería el framing o permitiría forjar
 * registros del ACCESS_LOG. Es defensa en profundidad: los valores que llegan
 * acá ya vienen validados (el parser del REQUEST restringe el charset del
 * FQDN y las IPs salen de inet_ntop).
 */
static void
sanitize_field(char *s) {
    if (s == NULL) {
        return;
    }
    for (; *s != '\0'; s++) {
        const unsigned char c = (unsigned char)*s;
        if (c <= ' ' || c > '~') {
            *s = '?';
        }
    }
}

static int
find_active(const char *username) {
    for (int i = 0; i < active_count; i++) {
        if (strncmp(active_users[i].username, username, MAX_USERNAME_LEN) == 0) {
            return i;
        }
    }
    return -1;
}

static int
find_all_time(const char *username) {
    for (int i = 0; i < all_time_count; i++) {
        if (strncmp(all_time_users[i].username, username, MAX_USERNAME_LEN) == 0) {
            return i;
        }
    }
    return -1;
}

/* Devuelve el índice del usuario en all_time_users, creándolo si no existía.
 * Devuelve -1 si falla la reserva de memoria. */
static int
get_or_create_all_time(const char *username) {
    int idx = find_all_time(username);
    if (idx >= 0) {
        return idx;
    }
    if (all_time_count == all_time_capacity) {
        int new_cap = all_time_capacity + GROW_STEP;
        user_info *grown = realloc(all_time_users, (size_t)new_cap * sizeof(user_info));
        if (grown == NULL) {
            return -1;
        }
        all_time_users = grown;
        all_time_capacity = new_cap;
    }
    idx = all_time_count++;
    memset(&all_time_users[idx], 0, sizeof(user_info));
    strncpy(all_time_users[idx].username, username, MAX_USERNAME_LEN - 1);
    all_time_users[idx].username[MAX_USERNAME_LEN - 1] = '\0';
    all_time_users[idx].sites_visited = NULL;
    all_time_users[idx].site_count = 0;
    all_time_users[idx].last_seen = time(NULL);
    return idx;
}

void
metrics_init(void) {
    total_connections = 0;
    current_connections = 0;
    max_concurrent_connections = 0;
    total_bytes_transferred = 0;
    server_start_time = time(NULL);
    active_count = 0;
    all_time_users = NULL;
    all_time_count = 0;
    all_time_capacity = 0;
}

int
metrics_connection_start(void) {
    if (current_connections >= MAX_CONNECTIONS) {
        return 1;  // al tope: no se contabiliza
    }
    total_connections++;
    current_connections++;
    if (current_connections > max_concurrent_connections) {
        max_concurrent_connections = current_connections;
    }
    return 0;
}

void
metrics_connection_end(void) {
    if (current_connections > 0) {
        current_connections--;
    }
}

void
metrics_bytes_transferred(ssize_t bytes) {
    if (bytes > 0) {
        total_bytes_transferred += (uint64_t)bytes;
    }
}

void
metrics_add_user(const char *username) {
    if (username == NULL) {
        return;
    }
    // Asegura la existencia en el histórico y refresca last_seen.
    int at = get_or_create_all_time(username);
    if (at >= 0) {
        all_time_users[at].last_seen = time(NULL);
    }
    // Alta en activos: si ya estaba, es una conexión más del mismo usuario.
    int idx = find_active(username);
    if (idx >= 0) {
        active_conns[idx]++;
        active_users[idx].last_seen = time(NULL);
        return;
    }
    if (active_count >= MAX_CONNECTIONS) {
        return;
    }
    idx = active_count++;
    memset(&active_users[idx], 0, sizeof(user_info));
    strncpy(active_users[idx].username, username, MAX_USERNAME_LEN - 1);
    active_users[idx].username[MAX_USERNAME_LEN - 1] = '\0';
    active_users[idx].last_seen = time(NULL);
    active_users[idx].sites_visited = NULL;  // los sitios viven en all_time
    active_users[idx].site_count = 0;
    active_conns[idx] = 1;
}

void
metrics_remove_user(const char *username) {
    if (username == NULL) {
        return;
    }
    int idx = find_active(username);
    if (idx < 0) {
        return;
    }
    // Baja de UNA conexión: el usuario sigue activo mientras le quede otra.
    active_conns[idx]--;
    if (active_conns[idx] <= 0) {
        // Compacta el arreglo moviendo el último al hueco.
        active_users[idx] = active_users[active_count - 1];
        active_conns[idx] = active_conns[active_count - 1];
        active_count--;
    }

    int at = find_all_time(username);
    if (at >= 0) {
        all_time_users[at].last_seen = time(NULL);
    }
}

void
metrics_add_user_site(const char *username, char *site, char *port, bool success) {
    if (username == NULL) {
        return;
    }
    int at = get_or_create_all_time(username);
    if (at < 0) {
        return;
    }
    user_info *u = &all_time_users[at];
    site_visit *v;
    if (u->site_count == MAX_SITES_PER_USER) {
        // ring lleno: se pisa la visita más vieja (site_start) y el inicio
        // avanza. El conteo ya no cambia; solo rota qué N visitas se guardan.
        v = &u->sites_visited[u->site_start];
        free(v->destination_host);
        free(v->destination_port);
        u->site_start = (u->site_start + 1) % MAX_SITES_PER_USER;
    } else {
        // Crece el arreglo de sitios de a GROW_STEP, con techo en el ring.
        if (u->site_count % GROW_STEP == 0) {
            int new_cap = u->site_count + GROW_STEP;
            if (new_cap > MAX_SITES_PER_USER) {
                new_cap = MAX_SITES_PER_USER;
            }
            site_visit *grown = realloc(u->sites_visited, (size_t)new_cap * sizeof(site_visit));
            if (grown == NULL) {
                return;
            }
            u->sites_visited = grown;
        }
        v = &u->sites_visited[u->site_count];
        u->site_count++;
    }
    v->destination_host = dup_str(site);
    v->destination_port = dup_str(port);
    sanitize_field(v->destination_host);
    sanitize_field(v->destination_port);
    v->timestamp = time(NULL);
    v->success = success;
    u->last_seen = time(NULL);
}

void
metrics_free(void) {
    for (int i = 0; i < all_time_count; i++) {
        user_info *u = &all_time_users[i];
        for (int j = 0; j < u->site_count; j++) {
            // recorre solo los slots ocupados del ring (con él lleno son
            // todos; si no, site_start es 0 y son los primeros site_count)
            site_visit *v = &u->sites_visited[(u->site_start + j) % MAX_SITES_PER_USER];
            free(v->destination_host);
            free(v->destination_port);
        }
        free(u->sites_visited);
    }
    free(all_time_users);
    all_time_users = NULL;
    all_time_count = 0;
    all_time_capacity = 0;
    active_count = 0;
}

uint64_t
metrics_get_total_connections(void) {
    return total_connections;
}

uint64_t
metrics_get_current_connections(void) {
    return current_connections;
}

uint64_t
metrics_get_max_concurrent_connections(void) {
    return max_concurrent_connections;
}

uint64_t
metrics_get_total_bytes_transferred(void) {
    return total_bytes_transferred;
}

time_t
metrics_get_server_uptime(void) {
    return time(NULL) - server_start_time;
}

int
metrics_get_user_count(void) {
    return active_count;
}

void
metrics_get_users(user_info *out, int max) {
    if (out == NULL || max <= 0) {
        return;
    }
    int n = active_count < max ? active_count : max;
    for (int i = 0; i < n; i++) {
        out[i] = active_users[i];  // copia superficial (no dueña de sites)
    }
}

int
metrics_get_all_time_user_count(void) {
    return all_time_count;
}

void
metrics_get_all_time_users(user_info *out, int max) {
    if (out == NULL || max <= 0) {
        return;
    }
    int n = all_time_count < max ? all_time_count : max;
    for (int i = 0; i < n; i++) {
        out[i] = all_time_users[i];  // copia superficial; NO liberar
    }
}

void
metrics_get_snapshot(metrics_snapshot *out) {
    if (out == NULL) {
        return;
    }
    out->historical_connections = total_connections;
    out->concurrent_connections = current_connections;
    out->max_concurrent = max_concurrent_connections;
    out->bytes_transferred = total_bytes_transferred;
    out->uptime_seconds = (uint64_t)(time(NULL) - server_start_time);
}

int
metrics_get_access_log(const char *username, char out[][ACCESS_LOG_LINE_LEN], int max) {
    if (out == NULL || max <= 0) {
        return 0;
    }
    const bool filter = (username != NULL && username[0] != '\0');

    int n = 0;
    for (int i = 0; i < all_time_count && n < max; i++) {
        const user_info *u = &all_time_users[i];
        if (filter && strncmp(u->username, username, MAX_USERNAME_LEN) != 0) {
            continue;
        }
        for (int j = 0; j < u->site_count && n < max; j++) {
            // del más viejo al más nuevo, arrancando en site_start (ring)
            const site_visit *v =
                &u->sites_visited[(u->site_start + j) % MAX_SITES_PER_USER];

            struct tm tm_utc;
            gmtime_r(&v->timestamp, &tm_utc);
            char ts[sizeof("YYYY-MM-DDThh:mm:ssZ")];
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

            snprintf(out[n], ACCESS_LOG_LINE_LEN, "%s %s:%s %s %s",
                     u->username, v->destination_host, v->destination_port,
                     ts, v->success ? "SUCCESS" : "FAIL");
            n++;
        }
    }
    return n;
}

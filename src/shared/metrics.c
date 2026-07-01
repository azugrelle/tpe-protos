#include "metrics.h"
#include <stdlib.h>
#include <string.h>

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
 *    el arranque. Es DUEÑO de sites_visited (alimenta ACCESS_LOG de T71).
 *  - active_users: subconjunto conectado ahora. Copia superficial de
 *    username/last_seen; NO es dueño de sites (evita doble free). Se maneja como
 *    conjunto de usernames únicos: varias conexiones del mismo usuario no
 *    duplican el entry (simplificación acorde al alcance del TP).
 */
static user_info active_users[MAX_CONNECTIONS];
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
    // Alta en activos (como conjunto: no duplica si ya está).
    int idx = find_active(username);
    if (idx >= 0) {
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
    // Compacta el arreglo moviendo el último al hueco.
    active_users[idx] = active_users[active_count - 1];
    active_count--;

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
    // Crece el arreglo de sitios de a GROW_STEP.
    if (u->site_count % GROW_STEP == 0) {
        int new_cap = u->site_count + GROW_STEP;
        site_visit *grown = realloc(u->sites_visited, (size_t)new_cap * sizeof(site_visit));
        if (grown == NULL) {
            return;
        }
        u->sites_visited = grown;
    }
    site_visit *v = &u->sites_visited[u->site_count];
    v->destination_host = dup_str(site);
    v->destination_port = dup_str(port);
    v->timestamp = time(NULL);
    v->success = success;
    u->site_count++;
    u->last_seen = time(NULL);
}

void
metrics_free(void) {
    for (int i = 0; i < all_time_count; i++) {
        for (int j = 0; j < all_time_users[i].site_count; j++) {
            free(all_time_users[i].sites_visited[j].destination_host);
            free(all_time_users[i].sites_visited[j].destination_port);
        }
        free(all_time_users[i].sites_visited);
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

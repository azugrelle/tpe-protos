#ifndef METRICS_H_9c1f4a2b3d7e4f5a8b6c0d1e2f3a4b5c
#define METRICS_H_9c1f4a2b3d7e4f5a8b6c0d1e2f3a4b5c

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>  // ssize_t

/**
 * metrics.c - contadores volátiles del servidor (se pierden al reiniciar) más
 *             seguimiento de usuarios activos e históricos.
 *
 * El módulo SOLO cuenta: no sabe de sockets ni de SOCKS5. Los que llaman
 * actualizan los contadores en el momento correcto; el monitoreo (T42) lee.
 *
 * Concurrencia: TODO el camino caliente corre en el hilo único del selector,
 * por lo que NO se usan locks. El hilo de DNS (T50) NO debe llamar a estas
 * funciones.
 *
 * API congelada: consumida por T42 (STATS/CONNECTIONS) y T71 (ACCESS_LOG).
 *
 * NOTA de adaptación: la referencia asumía MAX_USERNAME_LEN en args.h; en este
 * proyecto no existe y args.h vive en src/server/ (metrics está en src/shared/,
 * no debe depender de esa capa), así que se define acá. MAX_CONNECTIONS es el
 * tope de conexiones concurrentes del proxy, independiente de MAX_USERS (=10 en
 * args.h, que cuenta usuarios de línea de comandos, no conexiones).
 */

#define MAX_USERNAME_LEN 256
#define MAX_HOSTNAME_LEN 256
#define MAX_PORT_LEN 6
#define MAX_CONNECTIONS 511

/** largo máximo de una línea de ACCESS_LOG formateada (ver metrics_get_access_log) */
#define ACCESS_LOG_LINE_LEN 600

/** Un sitio visitado por un usuario (para ACCESS_LOG). */
typedef struct {
    char *destination_host;
    char *destination_port;
    time_t timestamp;
    bool success;
} site_visit;

/** Info de un usuario: nombre, última actividad y sitios visitados. */
typedef struct {
    char username[MAX_USERNAME_LEN];
    time_t last_seen;
    site_visit *sites_visited;  // arreglo dinámico (crece de a 10)
    int site_count;
} user_info;

/** Fotografía compacta de las métricas globales (comando STATS). */
typedef struct {
    uint64_t historical_connections;
    uint64_t concurrent_connections;
    uint64_t max_concurrent;
    uint64_t bytes_transferred;
    uint64_t uptime_seconds;
} metrics_snapshot;

/** Registra el timestamp de arranque. Llamar una vez al iniciar el server. */
void metrics_init(void);

/** Alta de conexión (tras accept()). Devuelve 1 si se llegó al tope
 *  (MAX_CONNECTIONS) y la conexión NO se contabilizó; 0 si quedó registrada. */
int metrics_connection_start(void);

/** Baja de conexión (al cerrarla). */
void metrics_connection_end(void);

/** Suma bytes copiados por el relay (ambos sentidos). Ignora valores <= 0. */
void metrics_bytes_transferred(ssize_t bytes);

/** Marca a un usuario como activo (conectado ahora). */
void metrics_add_user(const char *username);

/** Marca a un usuario como desconectado (lo saca de la lista de activos). */
void metrics_remove_user(const char *username);

/** Registra un sitio visitado por un usuario (queda en el histórico). */
void metrics_add_user_site(const char *username, char *site, char *port, bool success);

/** Libera toda la memoria dinámica del módulo. */
void metrics_free(void);

/* ---- Getters para los comandos de monitoreo (T42) ---- */

uint64_t metrics_get_total_connections(void);
uint64_t metrics_get_current_connections(void);
uint64_t metrics_get_max_concurrent_connections(void);
uint64_t metrics_get_total_bytes_transferred(void);
time_t   metrics_get_server_uptime(void);

/** Cantidad de usuarios activos ahora. */
int metrics_get_user_count(void);

/** Copia hasta max usuarios activos en out. Copia superficial (los punteros
 *  internos siguen siendo del módulo; NO liberar). Devuelve nada; usar
 *  metrics_get_user_count() para saber cuántos hay. */
void metrics_get_users(user_info *out, int max);

/** Cantidad de usuarios distintos vistos desde el arranque. */
int metrics_get_all_time_user_count(void);

/** Copia hasta max usuarios históricos en out (copia superficial; NO liberar). */
void metrics_get_all_time_users(user_info *out, int max);

/** Completa out con la fotografía global (comando STATS). */
void metrics_get_snapshot(metrics_snapshot *out);

/**
 * Arma líneas de ACCESS_LOG ("<user> <domain>:<port> <timestamp> <status>",
 * timestamp ISO8601 UTC), opcionalmente filtradas por username (NULL o ""
 * = todos los usuarios). Devuelve la cantidad de líneas escritas en out
 * (hasta max). Pensada para que la consuma el futuro handler del comando
 * ACCESS_LOG sin conocer la estructura interna de este módulo.
 *
 * Nota: las líneas salen agrupadas por usuario (orden cronológico dentro de
 * cada usuario, no globalmente entre usuarios).
 */
int metrics_get_access_log(const char *username, char out[][ACCESS_LOG_LINE_LEN], int max);

#endif

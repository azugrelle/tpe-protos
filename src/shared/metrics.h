#ifndef METRICS_H_9c1f4a2b3d7e4f5a8b6c0d1e2f3a4b5c
#define METRICS_H_9c1f4a2b3d7e4f5a8b6c0d1e2f3a4b5c

#include <stdint.h>

/**
 * metrics.c - contadores volátiles del servidor (se pierden al reiniciar).
 *
 * Estado global en memoria actualizado en los puntos calientes del proxy:
 *   - al aceptar una conexión         -> metrics_connection_opened()
 *   - al cerrar una conexión          -> metrics_connection_closed()
 *   - al copiar bytes en el relay     -> metrics_add_bytes() / *_directional()
 *   - al leer para el monitoreo       -> metrics_snapshot()
 *
 * Concurrencia: TODO el camino caliente corre en el hilo único del selector,
 * por lo que NO se usan locks. El hilo de DNS (T50) NO debe llamar a estas
 * funciones.
 *
 * API congelada: consumida por T42 (STATS/CONNECTIONS). No cambiar firmas.
 */

/** Fotografía de las métricas en un instante dado. */
struct metrics_snapshot {
    uint64_t historical_connections;  // total de conexiones desde el arranque
    uint64_t concurrent_connections;  // conexiones activas ahora mismo
    uint64_t max_concurrent;          // pico de conexiones concurrentes
    uint64_t bytes_transferred;       // bytes copiados en ambos sentidos
    uint64_t bytes_from_client;       // bytes cliente -> origen
    uint64_t bytes_from_origin;       // bytes origen -> cliente
    uint64_t uptime_seconds;          // segundos desde metrics_init()
};

/** Registra el timestamp de arranque. Llamar una vez al iniciar el server. */
void metrics_init(void);

/** Alta de conexión (llamar tras accept()). */
void metrics_connection_opened(void);

/** Baja de conexión (llamar al cerrarla). */
void metrics_connection_closed(void);

/** Suma n bytes al total transferido (sin distinguir sentido). */
void metrics_add_bytes(uint64_t n);

/** Suma n bytes en el sentido cliente -> origen (y al total). */
void metrics_add_bytes_from_client(uint64_t n);

/** Suma n bytes en el sentido origen -> cliente (y al total). */
void metrics_add_bytes_from_origin(uint64_t n);

/** Completa out con el estado actual de las métricas. */
void metrics_snapshot(struct metrics_snapshot *out);

#endif

#include "metrics.h"
#include <time.h>

/**
 * Estado global de métricas. Único, sin locks: todo el camino caliente corre
 * en el hilo del selector (ver metrics.h).
 */
static struct {
    uint64_t historical_connections;
    uint64_t concurrent_connections;
    uint64_t max_concurrent;
    uint64_t bytes_transferred;   // total en ambos sentidos
    uint64_t bytes_from_client;   // desglose opcional cliente -> origen
    uint64_t bytes_from_origin;   // desglose opcional origen -> cliente
    time_t   start_time;
} metrics;

void
metrics_init(void) {
    metrics.historical_connections = 0;
    metrics.concurrent_connections = 0;
    metrics.max_concurrent = 0;
    metrics.bytes_transferred = 0;
    metrics.bytes_from_client = 0;
    metrics.bytes_from_origin = 0;
    metrics.start_time = time(NULL);
}

void
metrics_connection_opened(void) {
    metrics.historical_connections++;
    metrics.concurrent_connections++;
    if (metrics.concurrent_connections > metrics.max_concurrent) {
        metrics.max_concurrent = metrics.concurrent_connections;
    }
}

void
metrics_connection_closed(void) {
    if (metrics.concurrent_connections > 0) {
        metrics.concurrent_connections--;
    }
}

void
metrics_add_bytes(uint64_t n) {
    metrics.bytes_transferred += n;
}

void
metrics_add_bytes_from_client(uint64_t n) {
    metrics.bytes_transferred += n;
    metrics.bytes_from_client += n;
}

void
metrics_add_bytes_from_origin(uint64_t n) {
    metrics.bytes_transferred += n;
    metrics.bytes_from_origin += n;
}

void
metrics_snapshot(struct metrics_snapshot *out) {
    if (out == NULL) {
        return;
    }
    out->historical_connections = metrics.historical_connections;
    out->concurrent_connections = metrics.concurrent_connections;
    out->max_concurrent = metrics.max_concurrent;
    out->bytes_transferred = metrics.bytes_transferred;
    out->bytes_from_client = metrics.bytes_from_client;
    out->bytes_from_origin = metrics.bytes_from_origin;
    out->uptime_seconds = (uint64_t)(time(NULL) - metrics.start_time);
}

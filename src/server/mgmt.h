#ifndef MGMT_H_qX2vB8nT4kW9cR1zL6pM3sH7dJ0fG5aY
#define MGMT_H_qX2vB8nT4kW9cR1zL6pM3sH7dJ0fG5aY

/**
 * mgmt.h -- servidor de monitoreo/administración del proxy SOCKSv5 (T32).
 *
 * Protocolo de texto orientado a línea (ver doc/monitoring_protocol.md),
 * servido en un socket pasivo propio (-L/-P) registrado en el mismo selector
 * que el proxy. Este módulo es dueño del ciclo de vida de cada sesión de
 * administración: acepta la conexión, parsea líneas con I/O parcial y
 * despacha los comandos.
 */

#include "selector.h"
#include "args.h"

/**
 * guarda la referencia a los argumentos del programa: AUTH valida contra la
 * tabla users[] (solo entradas con is_admin). Llamar una vez antes de aceptar
 * conexiones; `args' debe sobrevivir toda la ejecución (vive en el frame de
 * main).
 */
void
mgmt_init(const struct socks5args *args);

/** handler de aceptación de una nueva conexión entrante al monitoreo */
void
mgmt_passive_accept(struct selector_key *key);

/** libera el pool de sesiones reutilizables */
void
mgmt_pool_destroy(void);

#endif

#ifndef CONFIG_H_7e2d9b4c1f8a4e6b9c3d0a5f2b7e8c1d
#define CONFIG_H_7e2d9b4c1f8a4e6b9c3d0a5f2b7e8c1d

#include <stddef.h>

/**
 * config.c - parámetros del server ajustables en runtime vía el comando
 *            CONFIG del monitoreo.
 *
 * Solo memoria: los valores se pierden al reiniciar (volvería a los
 * defaults). El monitoreo escribe con los setters; el proxy lee con los
 * getters al crear conexiones NUEVAS — las conexiones vivas conservan los
 * valores con los que nacieron.
 *
 * Concurrencia: igual que metrics, todo el camino corre en el hilo único
 * del selector, por lo que NO se usan locks.
 *
 * La validación de protocolo (numérico, positivo, rango) es responsabilidad
 * del que llama a los setters; este módulo solo guarda. Los límites viven
 * acá para que validador y consumidores compartan la misma verdad.
 */

/** timeout de inactividad de una conexión, en segundos (máx 24h) */
#define CONFIG_TIMEOUT_MAX      86400
#define CONFIG_TIMEOUT_DEFAULT  300

/** tamaño de los buffers de I/O de una conexión del proxy, en bytes (máx
 *  1 MiB). El default replica el tamaño histórico de `struct socks5'. */
#define CONFIG_BUF_SIZE_MAX     1048576
#define CONFIG_BUF_SIZE_DEFAULT 2048

unsigned config_get_timeout(void);
void     config_set_timeout(unsigned seconds);

size_t   config_get_buf_size(void);
void     config_set_buf_size(size_t bytes);

#endif

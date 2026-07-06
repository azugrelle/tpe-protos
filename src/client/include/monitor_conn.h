#ifndef MONITOR_CONN_H_rV4kX9bN2tW7cQ1zL5pM8sH3dJ6fG0aY
#define MONITOR_CONN_H_rV4kX9bN2tW7cQ1zL5pM8sH3dJ6fG0aY

/**
 * monitor_conn.h -- transporte del cliente de monitoreo: conexión TCP
 * bloqueante y framing por líneas del protocolo (texto terminado en '\n',
 * ver src/docs/monitoring_protocol.md).
 *
 * Todas las funciones reportan sus errores por stderr antes de devolver el
 * fallo, así el llamador solo decide el código de salida.
 */

#include <stdbool.h>
#include <stddef.h>

/** longitud máxima de una línea del protocolo, contando el '\n' final */
#define MONITOR_MAX_LINE 512

struct monitor_conn {
    int    fd;

    /**
     * bytes recibidos y todavía no entregados como líneas. Un recv puede
     * traer media línea o varias juntas: lo pendiente vive acá entre
     * llamadas a monitor_conn_recv_line.
     */
    char   buff[1024];
    size_t start;   /**< primer byte no consumido */
    size_t len;     /**< bytes válidos en buff */
};

/**
 * resuelve host:serv (IPv4, IPv6 o nombre) y conecta probando cada candidato.
 * Deja `conn' listo para usar y devuelve true; false si no se pudo conectar.
 */
bool
monitor_conn_open(struct monitor_conn *conn, const char *host,
                  const char *serv);

/**
 * envía `line' + '\n', tolerando envíos parciales. Rechaza líneas que
 * excedan MONITOR_MAX_LINE (el server las cortaría junto con la conexión).
 */
bool
monitor_conn_send_line(struct monitor_conn *conn, const char *line);

/**
 * devuelve la próxima línea recibida, sin el fin de línea ('\r' final
 * incluido) y NUL-terminada. El puntero entra en el buffer interno: vale
 * hasta la próxima llamada. NULL ante cualquier desvío, todos fatales para
 * la sesión: cierre del server, error de I/O, timeout de respuesta, línea
 * más larga que el buffer o EOF con una línea a medias.
 */
const char *
monitor_conn_recv_line(struct monitor_conn *conn);

void
monitor_conn_close(struct monitor_conn *conn);

#endif

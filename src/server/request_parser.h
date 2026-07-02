#ifndef REQUEST_H_zX8cV4bN2mK6qW9tR1yU7iO3pL5aS0dF
#define REQUEST_H_zX8cV4bN2mK6qW9tR1yU7iO3pL5aS0dF

#include "buffer.h"

/*
 * request_parser.h -- estado REQUEST de SOCKSv5 (RFC 1928 §4).
 *
 * Stub para M1: el parseo real del REQUEST se implementa en T21. Por ahora
 * solo existe la estructura para que la `union' de estados de `struct socks5'
 * tenga su tamaño, y el estado REQUEST_READ cierre la conexión.
 */
struct request_st {
    /** buffers de I/O (heredados del `struct socks5') */
    buffer *rb, *wb;
};

#endif

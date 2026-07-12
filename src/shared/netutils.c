#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

extern const char *
sockaddr_to_human(char *buff, const size_t buffsize,
                  const struct sockaddr *addr) {
    if(buffsize == 0) {
        return buff;
    }
    if(addr == 0) {
        snprintf(buff, buffsize, "null");
        return buff;
    }
    in_port_t port;
    void *p = 0x00;
    bool handled = false;

    switch(addr->sa_family) {
        case AF_INET:
            p    = &((struct sockaddr_in *) addr)->sin_addr;
            port =  ((struct sockaddr_in *) addr)->sin_port;
            handled = true;
            break;
        case AF_INET6:
            p    = &((struct sockaddr_in6 *) addr)->sin6_addr;
            port =  ((struct sockaddr_in6 *) addr)->sin6_port;
            handled = true;
            break;
    }
    if(handled) {
        if (inet_ntop(addr->sa_family, p,  buff, buffsize) == 0) {
            snprintf(buff, buffsize, "unknown ip");
        }
    } else {
        snprintf(buff, buffsize, "unknown");
    }

    /* inet_ntop y snprintf terminan en NUL dentro de buffsize, así que
     * len <= buffsize - 1 y el espacio restante nunca es cero. */
    size_t len = strlen(buff);
    if(len + 1 < buffsize) {
        buff[len++] = ':';
        buff[len]   = 0;
    }

    if(handled) {
        snprintf(buff + len, buffsize - len, "%d", ntohs(port));
    }

    return buff;
}

int
sock_blocking_write(const int fd, buffer *b) {
        int  ret = 0;
    ssize_t  nwritten;
	 size_t  n;
	uint8_t *ptr;

    do {
        ptr = buffer_read_ptr(b, &n);
        nwritten = send(fd, ptr, n, MSG_NOSIGNAL);
        if (nwritten > 0) {
            buffer_read_adv(b, nwritten);
        } else /* if (errno != EINTR) */ {
            ret = errno;
            break;
        }
    } while (buffer_can_read(b));

    return ret;
}

int
sock_blocking_copy(const int source, const int dest) {
    int ret = 0;
    char buf[4096];
    ssize_t nread;
    while ((nread = recv(source, buf, N(buf), 0)) > 0) {
        char* out_ptr = buf;
        ssize_t nwritten;
        do {
            nwritten = send(dest, out_ptr, nread, MSG_NOSIGNAL);
            if (nwritten > 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else /* if (errno != EINTR) */ {
                ret = errno;
                goto error;
            }
        } while (nread > 0);
    }
    error:

    return ret;
}


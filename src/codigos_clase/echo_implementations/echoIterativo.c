// Cada iteración acepta a 1 solo cliente. No es eficiente

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

typedef struct {
    int fd;
    int active;
    char buffer[BUFFER_SIZE];
    size_t buffer_len;
} client_t;

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    client_t clients[MAX_CLIENTS] = {0};

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Set server socket to non-blocking
    if (set_nonblocking(server_fd) == -1) {
        perror("set_nonblocking failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) == -1) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Non-blocking echo server listening on port %d (max %d clients)\n", PORT, MAX_CLIENTS);

    while (1) {
        // Try to accept new connections
        int new_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);

        if (new_fd != -1) {
            // Find a free slot
            int slot = -1;

            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (!clients[i].active) {
                    slot = i;
                    break;
                }
            }

            if (slot != -1) {
                // Set client socket to non-blocking
                if (set_nonblocking(new_fd) == -1) {
                    perror("set_nonblocking client failed");
                    close(new_fd);
                } else {
                    clients[slot].fd = new_fd;
                    clients[slot].active = 1;
                    clients[slot].buffer_len = 0;

                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

                    printf("Accepted connection from %s:%d (slot %d)\n",
                           client_ip, ntohs(client_addr.sin_port), slot);
                }
            } else {
                printf("Max clients reached, rejecting connection\n");
                close(new_fd);
            }
        } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
            perror("accept failed");
        }

        // Iterate through all active clients
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].active) {
                continue;
            }

            // Try to read from client
            ssize_t bytes_read = read(clients[i].fd, clients[i].buffer, BUFFER_SIZE);

            if (bytes_read > 0) {
                printf("Client %d: received %zd bytes\n", i, bytes_read);

                // Try to echo back immediately
                ssize_t bytes_written = write(clients[i].fd, clients[i].buffer, bytes_read);

                if (bytes_written == -1) {
                    if (errno == EWOULDBLOCK || errno == EAGAIN) {
                        printf("Client %d: write would block (data lost in this naive implementation)\n", i);
                    } else {
                        perror("write failed");
                        close(clients[i].fd);
                        clients[i].active = 0;
                        printf("Client %d: connection closed due to write error\n", i);
                    }
                } else if (bytes_written < bytes_read) {
                    printf("Client %d: partial write %zd/%zd (data lost in this naive implementation)\n",
                           i, bytes_written, bytes_read);
                }
            } else if (bytes_read == 0) {
                // Client closed connection
                printf("Client %d: closed connection\n", i);
                close(clients[i].fd);
                clients[i].active = 0;
            } else {
                // Read error
                if (errno != EWOULDBLOCK && errno != EAGAIN) {
                    perror("read failed");
                    close(clients[i].fd);
                    clients[i].active = 0;
                    printf("Client %d: connection closed due to read error\n", i);
                }

                // EWOULDBLOCK/EAGAIN means no data available, which is normal
            }
        }

        // Small sleep to avoid busy-waiting and consuming 100% CPU
        usleep(1000); // 1ms
    }

    close(server_fd);
    return 0;
}
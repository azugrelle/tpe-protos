// Servidor echo simple: acepta 1 solo cliente y le devuelve lo que le envía. No usa select ni poll ni epoll.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    char buffer[BUFFER_SIZE] = {0};
    ssize_t bytes_read;

    /*
     * 1. Crear el socket pasivo del servidor.
     *
     * AF_INET      → IPv4
     * SOCK_STREAM  → TCP
     * 0            → el SO elige TCP automáticamente según los dos anteriores
     */
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    /*
     * SO_REUSEADDR: Permite reutilizar rápidamente el puerto luego de cerrar el servidor.
     * Nos permite hacer una especie de load balancing entre procesos
    */
    int opt = 1;

    if (setsockopt(
            server_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &opt,
            sizeof(opt)
        ) == -1) {

        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    /*
     * Inicializamos toda la estructura en 0 antes de completarla.
     */
    memset(&server_addr, 0, sizeof(server_addr));

    /*
     * 2. Definir en qué dirección y puerto escuchará el servidor. Armamos el struct
     */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    /*
     * 3. Asociar el socket con esa IP y ese puerto.
     */
    if (bind(
            server_fd,
            (struct sockaddr *)&server_addr,
            sizeof(server_addr)
        ) == -1) {

        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    /*
     * 4. Convertirlo en socket pasivo: queda esperando conexiones.
     * El 10 es el tamaño máximo aproximado de la cola de conexiones pendientes.
    */
    if (listen(server_fd, 10) == -1) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Echo server listening on port %d\n", PORT);

    /*
     * 5. Esperar a que un cliente se conecte.
     *
     * accept() es bloqueante: el programa queda frenado acá
     * hasta que alguien intente conectarse.
     *
     * Acá hacemos 1 solo accept. Solo podemos atender a 1 cliente por vez.
     */
    if ((client_socket = accept(
            server_fd,
            (struct sockaddr *)&client_addr,
            &client_addr_len
        )) == -1) {

        perror("accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    /*
     * Mostrar desde qué IP y puerto se conectó el cliente.
     */
    char client_ip[INET_ADDRSTRLEN];

    inet_ntop(
        AF_INET,
        &client_addr.sin_addr,
        client_ip,
        INET_ADDRSTRLEN
    );

    printf(
        "Accepted connection from %s:%d\n",
        client_ip,
        ntohs(client_addr.sin_port)
    );

    /*
     * 6. Leer datos del cliente y devolverle exactamente lo recibido.
     */
    while ((bytes_read = read(client_socket, buffer, BUFFER_SIZE)) > 0) { // el read es bloqueante
        printf("Received %zd bytes from client\n", bytes_read);

        if (write(client_socket, buffer, bytes_read) == -1) { // lo que leemos, lo escribimos. El write podria ser bloqueante pero aca no deberia creo
            perror("write failed");
            break;
        }

        memset(buffer, 0, BUFFER_SIZE);
    }

    /*
     * read() devuelve:
     *
     * > 0  → cantidad de bytes leídos
     *   0  → el cliente cerró ordenadamente la conexión
     *  -1  → ocurrió un error
     */
    if (bytes_read == -1) {
        perror("read failed");
    } else {
        printf("Client closed the connection.\n");
    }

    close(client_socket);
    close(server_fd);

    return EXIT_SUCCESS;
}
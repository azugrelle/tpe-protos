#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "logger.h"
#include "util.h"

#define MAXPENDING 5 // Maximum outstanding connection requests -> hasta que los atienda
#define BUFSIZE 256
#define MAX_ADDR_BUFFER 128

static char addrBuffer[MAX_ADDR_BUFFER];
/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setupTCPServerSocket(const char *service) {
	// Construct the server address structure
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;             // Any address family
	addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port -> socket pasivo para aceptar pedidos de conexion, para que escuche en cualquier IP
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	struct addrinfo *servAddr; 			// List of server addresses
	int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr); // NULL=escucho pedidos en cualquier IP, service=puerto a escuchar, addrCriteria=criterios de busqueda, servAddr=lista de direcciones que cumplen con los criterios
	if (rtnVal != 0) { // No se pudo resolver el puerto, o no se pudo crear el socket
		log(FATAL, "getaddrinfo() failed %s", gai_strerror(rtnVal));
		return -1;
	}

	int servSock = -1;
	// Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio, sin especificar una IP en particular
	// Iteramos y hacemos el bind por alguna de ellas, la primera que funcione, ya sea la general para IPv4 (0.0.0.0) o IPv6 (::/0) .
	// Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
	for (struct addrinfo *addr = servAddr; addr != NULL && servSock == -1; addr = addr->ai_next) {
		errno = 0;
		// Create a TCP socket
		servSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (servSock < 0) {
			log(DEBUG, "Cant't create socket on %s : %s ", printAddressPort(addr, addrBuffer), strerror(errno));  
			continue;       // Socket creation failed; try next address
		}

		// Bind to ALL the address and set socket to listen
		if ((bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0) && (listen(servSock, MAXPENDING) == 0)) { // me pongo a escuchar en ese puerto, si no puedo, pruebo con el siguiente. 
			//El listen puede fallar si el puerto ya está en uso y no es compartido, o porque no soy root y quiero escuchar en un puerto privilegiado.
			// Print local address of socket
			struct sockaddr_storage localAddr;
			socklen_t addrSize = sizeof(localAddr);
			if (getsockname(servSock, (struct sockaddr *) &localAddr, &addrSize) >= 0) {
				printSocketAddress((struct sockaddr *) &localAddr, addrBuffer);
				log(INFO, "Binding to %s", addrBuffer);
			}
		} else {
			log(DEBUG, "Cant't bind %s", strerror(errno));  
			close(servSock);  // Close and try with the next one
			servSock = -1;
		}
	}

	freeaddrinfo(servAddr);

	return servSock; // me retorna el socket pasivo. Sobre este socket se puede hacer accept() para aceptar conexiones entrantes, NO un recv() o send() porque no es un socket conectado a un cliente en particular, sino que es un socket que escucha pedidos de conexion entrantes.
}

// recibe el socket pasivo y hace un accept() para aceptar la conexion entrante de un cliente. Devuelve el socket conectado al cliente, o -1 si hubo error
int acceptTCPConnection(int servSock) {
	struct sockaddr_storage clntAddr; // Client address
	// Set length of client address structure (in-out parameter)
	socklen_t clntAddrLen = sizeof(clntAddr);

	// Wait for a client to connect
	int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen); // le paso el puntero a la estructura para poder despues imprimir la direccion del cliente que se conecto
	// si esto fuera UDP y no TCP, es obligatorio pasarle la direccion del cliente que me envio el datagrama, porque si no, no se como responderle. En TCP, el accept() devuelve un socket conectado al cliente, y ya sabe a quien responderle, por eso no es obligatorio pasarle la direccion del cliente.
	if (clntSock < 0) {
		log(ERROR, "accept() failed");
		return -1;
	}

	// clntSock is connected to a client!
	printSocketAddress((struct sockaddr *) &clntAddr, addrBuffer);
	log(INFO, "Handling client %s", addrBuffer);

	return clntSock; // me devuelve el socket conectado al cliente, sobre este socket se puede hacer recv() y send() para recibir y enviar datos al cliente
}

// recibe el socket activo conectado al cliente y hace un echo de los datos que recibe, hasta que el cliente cierre la conexion. Devuelve 0 si todo ok, o -1 si hubo error
int handleTCPEchoClient(int clntSocket) {
	char buffer[BUFSIZE]; // Buffer for echo string
	// Receive message from client
	ssize_t numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);
	if (numBytesRcvd < 0) {
		log(ERROR, "recv() failed");
		return -1;   // TODO definir codigos de error
	}

	// Send received string and receive again until end of stream
	while (numBytesRcvd > 0) { // 0 indicates end of stream
		// Echo message back to client
		ssize_t numBytesSent = send(clntSocket, buffer, numBytesRcvd, 0);
		if (numBytesSent < 0) {
			log(ERROR, "send() failed");
			return -1;   // TODO definir codigos de error
		}
		else if (numBytesSent != numBytesRcvd) {
			log(ERROR, "send() sent unexpected number of bytes ");
			return -1;   // TODO definir codigos de error
		}

		// See if there is more data to receive
		numBytesRcvd = recv(clntSocket, buffer, BUFSIZE, 0);
		if (numBytesRcvd < 0) {
			log(ERROR, "recv() failed");
			return -1;   // TODO definir codigos de error
		}
	}
	
	// cuando numBytesRcvd = 0 significa que el cliente cerro la conexion, por lo que cerramos el socket y salimos
	close(clntSocket);
	return 0;
}
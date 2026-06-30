#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "logger.h"
#include "tcpClientUtil.h"

#define BUFSIZE 512

// se conecta a un servidor TCP, le envia un string y espera recibirlo de vuelta
int main(int argc, char *argv[]) {

	if (argc != 4) {
		log(FATAL, "usage: %s <Server Name/Address> <Echo Word> <Server Port/Name>", argv[0]);
	}

	char *server = argv[1];     // First arg: server name IP address 
	char *echoString = argv[2]; // Second arg: string to echo

	// Third arg server port
	char * port = argv[3];

	// Create a reliable, stream socket using TCP
	int sock = tcpClientSocket(server, port); // nos devuelve un socket que se puede conectar a ese servidor y puerto
	if (sock < 0) {
		log(FATAL, "socket() failed")
	}

	size_t echoStringLen = strlen(echoString); // Determine input length

	// Send the string to the server
	ssize_t numBytes = send(sock, echoString, echoStringLen, 0); 
	// send es similar a la funcion write
	// Send es bloqueante porque es confiable y espera a q te devuelva que le llego.
	// Si del otro lado se cae, o si el buffer del otro lado está lleno queda bloqueado
	//  Para que sea no bloqueante, se le puede mandar un flag MSG_DONTWAIT, pero no es confiable, porque no te asegura que le llegue al otro lado.
	// send devuelve la cantidad de bytes que pudo enviar, que puede ser menor a la cantidad de bytes que le pediste enviar. Por eso es importante chequear el valor de retorno.
	if (numBytes < 0 || numBytes != echoStringLen) // si send devuelve -1 es porque hubo un error, si devuelve menos de lo que le pediste enviar es porque no pudo enviar todo
		log(FATAL, "send() failed expected %zu sent %zu", echoStringLen, numBytes);

	// Receive the same string back from the server
	unsigned int totalBytesRcvd = 0; // Count of total bytes received
	log(INFO, "Received: ")     // Setup to print the echoed string
	while (totalBytesRcvd < echoStringLen && numBytes >=0) { // verifico si el servidor me devolvio todo lo que le envie, si no, sigo recibiendo. Tambien verifico que no haya habido un error en el recv
		char buffer[BUFSIZE]; 
		/* Receive up to the buffer size (minus 1 to leave space for a null terminator) bytes from the sender */
		numBytes = recv(sock, buffer, BUFSIZE - 1, 0); 
		if (numBytes < 0) {
			log(ERROR, "recv() failed")
		}  
		else if (numBytes == 0) // recv devuelve 0 si se cerro la conexion del otro lado, es decir, si el servidor se cayo o cerro la conexion
			log(ERROR, "recv() connection closed prematurely")
		else {
			totalBytesRcvd += numBytes; // Keep tally of total bytes
			buffer[numBytes] = '\0';    // Terminate the string!
			log(INFO, "%s", buffer);      // Print the echo buffer
		}
	}

	close(sock); // se queda esperando a que se cierre la conexion 
	return 0;
}
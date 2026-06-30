/* Basado en findsrv.c del libro de Stevens */

#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include "logger.h"
#include "util.h"

// es una especie de dig o host, que dado un nombre de host y un servicio, imprime la informacion de las direcciones (no intenta conectarse)
// nosotros vamos a tener que intentar conectarnos tambien
int
main(int argc, char *argv[])
{
	struct addrinfo		*ailist, *aip;
	struct addrinfo		hint;
	int 			err;
	char 	*service;
	char *addrString;
	char 	addr[64];

	if (argc < 2)
		log(FATAL, "usage: %s host [service]", argv[0]);
	if ( argc >= 3 )
		service = argv[2];
	else
		service =  NULL;

	addrString = argv[1];

	memset(&hint, 0, sizeof(hint));
	hint.ai_flags = AI_CANONNAME; 
	if ((err = getaddrinfo(addrString, service, &hint, &ailist)) != 0)
		log(FATAL, "getaddrinfo error: %s", gai_strerror(err)); // gai_strerror es una funcion que convierte el error en un string legible
	for (aip = ailist; aip != NULL; aip = aip->ai_next) {
		printFlags(aip);
		printf(" family: %s ", printFamily(aip));
		printf(" type: %s ", printType(aip));
		printf(" protocol %s ", printProtocol(aip));
		printf("\n\thost %s", aip->ai_canonname? aip->ai_canonname:"-");
		printf("address: %s", printAddressPort(aip, addr));
		putchar('\n');
	}
	freeaddrinfo(ailist);
	return 0;
}
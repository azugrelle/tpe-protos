#ifndef USER_AUTH_UTILS_H_dP4vNq2ZsYcW7RhKtXoLmF98Bj
#define USER_AUTH_UTILS_H_dP4vNq2ZsYcW7RhKtXoLmF98Bj

#include <stdint.h>

/**
 * user_auth_utils.c - tabla de usuarios del proxy (autenticación RFC1929).
 *
 * Se carga a partir de los usuarios pasados por línea de comandos
 * (ver args.h / -u usuario:contraseña) y es consumida por el flujo de
 * autenticación SOCKS5 para validar credenciales.
 */

/**
 * da de alta un usuario nuevo.
 * Retorna 1 si se pudo dar de alta, 0 si los datos son inválidos, ya
 * existía el usuario, o no hay memoria disponible.
 */
int
create_user_credentials(const char *username, const char *password);

/** libera la tabla de usuarios. Llamar al cerrar el servidor. */
void
free_user_credentials(void);


/** Checkea si el par usuario - contraseña existe
 * Retorna 0x00 si el par es válido, 0x01 si no lo es
*/
uint8_t
check_if_valid_credentials(const char * username, const char * password);


#endif

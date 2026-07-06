#ifndef USER_AUTH_UTILS_H_dP4vNq2ZsYcW7RhKtXoLmF98Bj
#define USER_AUTH_UTILS_H_dP4vNq2ZsYcW7RhKtXoLmF98Bj

#include <stdint.h>
#include <stdbool.h>

/**
 * user_auth_utils.c - tabla de usuarios del proxy (autenticación RFC1929) y
 * del puerto de monitoreo (usuarios con is_admin).
 *
 * Se carga a partir de los usuarios pasados por línea de comandos
 * (ver args.h / -u, -a usuario:contraseña) y es consumida por el flujo de
 * autenticación SOCKS5 (check_if_valid_credentials) y por el login del
 * monitoreo (check_if_valid_admin_credentials). También es la tabla que
 * modifican en runtime los comandos ADD_USER/DEL_USER del monitoreo.
 */

/**
 * da de alta un usuario nuevo (uso exclusivo de la carga inicial por línea de
 * comandos, ver main.c).
 * Retorna 1 si se pudo dar de alta, 0 si los datos son inválidos, ya
 * existía el usuario, o no hay memoria disponible.
 */
int
create_user_credentials(const char *username, const char *password, bool is_admin);

/** libera la tabla de usuarios. Llamar al cerrar el servidor. */
void
free_user_credentials(void);


/** Checkea si el par usuario - contraseña existe
 * Retorna 0x00 si el par es válido, 0x01 si no lo es
*/
uint8_t
check_if_valid_credentials(const char * username, const char * password);

/**
 * igual que check_if_valid_credentials, pero además exige que el usuario
 * tenga is_admin=true. La usa el login del puerto de monitoreo (mgmt.c).
 * Retorna 0x00 si el par es válido y es admin, 0x01 en cualquier otro caso.
 */
uint8_t
check_if_valid_admin_credentials(const char * username, const char * password);

/** true si el servidor fue arrancado con al menos un usuario (-u): auth obligatoria */
int
auth_is_required(void);

/** resultado de un alta en runtime (ADD_USER) */
enum user_add_result {
    USER_ADD_OK,
    USER_ADD_INVALID,
    USER_ADD_EXISTS,
    USER_ADD_FULL,
};

/**
 * da de alta un usuario en runtime (ADD_USER). Siempre no-admin: el
 * protocolo de monitoreo no tiene forma de pedir admin por esta vía.
 * Respeta el tope MAX_USERS (args.h) compartido con los usuarios cargados
 * por línea de comandos.
 */
enum user_add_result
add_user_credentials(const char *username, const char *password);

/** resultado de una baja en runtime (DEL_USER) */
enum user_del_result {
    USER_DEL_OK,
    USER_DEL_NOT_FOUND,
    USER_DEL_LAST_ADMIN,
};

/**
 * da de baja un usuario en runtime (DEL_USER). No corta conexiones ya
 * establecidas de ese usuario (el relay no vuelve a mirar credenciales):
 * solo impide logins nuevos, tanto en el proxy SOCKS como en el monitoreo.
 * Rechaza la baja del único usuario con is_admin=true (USER_DEL_LAST_ADMIN)
 * para no perder el acceso al monitoreo hasta reiniciar el proceso.
 */
enum user_del_result
delete_user_credentials(const char *username);

#endif

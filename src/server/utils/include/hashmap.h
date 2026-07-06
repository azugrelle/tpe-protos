#ifndef HASHMAP_H_wN3rT8kLpQ2xVb6mYcJ0hFa4ZsD7Ru9E
#define HASHMAP_H_wN3rT8kLpQ2xVb6mYcJ0hFa4ZsD7Ru9E

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// 255 caracteres útiles + NUL: el protocolo de monitoreo y RFC 1929 admiten
// usernames/passwords de hasta 255 bytes, y el -1 del NUL lo descuenta
// MAX_CREDENTIAL_LEN (user_auth_utils.c)
#define ENTRY_LENGTH 256

typedef struct static_entry {
    char key[ENTRY_LENGTH];     // name
    char value[ENTRY_LENGTH];   // pass
    int present;
    int is_admin;
} static_entry;

typedef struct hashmap {
    static_entry *entries;
    size_t size;
    size_t capacity;
} hashmap_t;


hashmap_t *hashmap_create(size_t capacity);
void hashmap_destroy(hashmap_t *map);
const static_entry *hashmap_get(const hashmap_t *map, const char *key);
int hashmap_insert(hashmap_t *map, const char * key, const char * value, int is_admin);
/** borra una entrada preservando el probing lineal del resto del cluster.
 *  Retorna 1 si se borró, 0 si la key no estaba. */
int hashmap_delete(hashmap_t *map, const char *key);

#endif


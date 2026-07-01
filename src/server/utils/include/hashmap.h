#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define ENTRY_LENGTH 255

typedef struct static_entry {
    char key[ENTRY_LENGTH];     // name
    char value[ENTRY_LENGTH];   // pass
    int present;
} static_entry;

typedef struct hashmap {
    static_entry *entries;
    size_t size;
    size_t capacity;
} hashmap_t;


hashmap_t *hashmap_create(size_t capacity);
void hashmap_destroy(hashmap_t *map);
const static_entry *hashmap_get(const hashmap_t *map, const char *key);
int hashmap_insert(hashmap_t *map, const char * key, const char * value);


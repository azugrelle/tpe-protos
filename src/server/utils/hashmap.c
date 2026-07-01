#include "include/hashmap.h"


static unsigned long _hash(const char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

static hashmap_t *rehash(hashmap_t *map, size_t new_capacity) {
    if (new_capacity <= map->capacity) {
        return map;
    }
    static_entry * new_entries = calloc(new_capacity, sizeof(static_entry));
    if (!new_entries) {
        return NULL;
    }
    for (size_t i = 0; i < map->capacity; i++) {
        if (map->entries[i].present){
            unsigned long hash = _hash(map->entries[i].key);
            size_t position = hash % new_capacity;
            while (new_entries[position].present) {
                position = (position + 1) % new_capacity;
            }
            new_entries[position] = map->entries[i];
        }
    }

    free(map->entries);
    map->entries = new_entries;
    map->capacity = new_capacity;
    return map;
}


hashmap_t *hashmap_create(size_t capacity) {
    hashmap_t * map = malloc(sizeof(hashmap_t));
    if (!map) {
        return NULL;
    }

    map->entries = calloc(capacity, sizeof(static_entry));
    if (!map->entries) {
        free(map);
        return NULL;
    }

    map->size=0;
    map->capacity=capacity;
    return map;
}


void hashmap_destroy(hashmap_t *map) {
    if(map) {
        if(map->entries) {
            free(map->entries);
        }
        free(map);
    }
}


const static_entry *hashmap_get(const hashmap_t *map, const char *key) {
    unsigned long hash = _hash(key);
    size_t position = hash % map->capacity;
    size_t probes = 0;

    while (probes < map->capacity && map->entries[position].present) {
        if (strcmp(map->entries[position].key, key) == 0) {
            return &(map->entries[position]);
        }
        position = (position + 1) % map->capacity;
        probes++;
    }

    return NULL;
}

int hashmap_insert(hashmap_t *map, const char * key, const char * value) {
    unsigned long hash = _hash(key);
    size_t position = hash % map->capacity;
    size_t probes = 0;

    while (probes < map->capacity && map->entries[position].present) {
        position = (position + 1) % map->capacity;
        probes++;
    }

    if (probes < map->capacity) {
        strncpy(map->entries[position].key, key, ENTRY_LENGTH - 1);
        map->entries[position].key[ENTRY_LENGTH - 1] = '\0';
        strncpy(map->entries[position].value, value, ENTRY_LENGTH - 1);
        map->entries[position].value[ENTRY_LENGTH - 1] = '\0';
        map->entries[position].present = 1;
        map->size++;
        return 1;
    }

    // tabla llena: agrandar y reintentar, usando el resultado real del reintento
    if (rehash(map, map->capacity * 2) == NULL) {
        return 0;
    }
    return hashmap_insert(map, key, value);
}
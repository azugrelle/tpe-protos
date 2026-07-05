#include <stdio.h>
#include <stdint.h>
#include "include/hashmap.h"
#include "include/user_auth_utils.h"

#define HASHMAP_SIZE 32
#define MAX_CREDENTIAL_LEN (ENTRY_LENGTH - 1)

hashmap_t * user_credentials = NULL;


// hashmap_t *hashmap_create(size_t capacity);
// void hashmap_destroy(hashmap_t *map);
// const static_entry *hashmap_get(const hashmap_t *map, const char *key);
// int hashmap_insert(const hashmap_t *map, const char * key, const char * value);



int create_user_credentials(const char *username, const char *password) {
    if (username == NULL || password == NULL
        || username[0] == '\0' || password[0] == '\0'
        || strlen(username) > MAX_CREDENTIAL_LEN
        || strlen(password) > MAX_CREDENTIAL_LEN) {
        return 0;
    }
    if (user_credentials == NULL) {
        user_credentials = hashmap_create(HASHMAP_SIZE);
        if (user_credentials == NULL) {
            return 0;
        }
    }
    const static_entry * existing_user = hashmap_get(user_credentials, username);
    if (existing_user != NULL) {
        printf("User %s already exists\n", username);
        return 0;
    }
    return hashmap_insert(user_credentials, username, password) != 0;
}

void free_user_credentials() {
    if (user_credentials != NULL) {
        hashmap_destroy(user_credentials);
        user_credentials = NULL;
    }
}

uint8_t check_if_valid_credentials(const char * username, const char * password) {
    if (user_credentials == NULL) {
        return 0x01;
    }
    const static_entry * user_entry = hashmap_get(user_credentials, username);
    if (user_entry == NULL) {
        return 0x01;
    }
    if (strcmp(user_entry->value, password) == 0) {
        return 0x00;
    } else {
        return 0x01;
    }
}


int auth_is_required(void) {
    return user_credentials != NULL;
}
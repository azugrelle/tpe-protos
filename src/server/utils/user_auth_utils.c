#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include "include/hashmap.h"
#include "include/user_auth_utils.h"
#include "../include/args.h"

#define HASHMAP_SIZE 32
#define MAX_CREDENTIAL_LEN (ENTRY_LENGTH - 1)

hashmap_t * user_credentials = NULL;

/** username: charset a-zA-Z0-9_, longitud 1..MAX_CREDENTIAL_LEN (protocolo de monitoreo §2) */
static bool
is_valid_username(const char *username) {
    if (username == NULL || username[0] == '\0') {
        return false;
    }
    size_t len = strlen(username);
    if (len > MAX_CREDENTIAL_LEN) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char) username[i];
        if (!isalnum(c) && c != '_') {
            return false;
        }
    }
    return true;
}

static bool
is_valid_password(const char *password) {
    return password != NULL && password[0] != '\0' && strlen(password) <= MAX_CREDENTIAL_LEN;
}

int create_user_credentials(const char *username, const char *password, bool is_admin) {
    if (!is_valid_username(username) || !is_valid_password(password)) {
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
    return hashmap_insert(user_credentials, username, password, is_admin) != 0;
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

uint8_t check_if_valid_admin_credentials(const char * username, const char * password) {
    if (user_credentials == NULL) {
        return 0x01;
    }
    const static_entry * user_entry = hashmap_get(user_credentials, username);
    if (user_entry == NULL || !user_entry->is_admin) {
        return 0x01;
    }
    return strcmp(user_entry->value, password) == 0 ? 0x00 : 0x01;
}


int auth_is_required(void) {
    return user_credentials != NULL;
}

enum user_add_result add_user_credentials(const char *username, const char *password) {
    if (!is_valid_username(username) || !is_valid_password(password)) {
        return USER_ADD_INVALID;
    }
    if (user_credentials == NULL) {
        user_credentials = hashmap_create(HASHMAP_SIZE);
        if (user_credentials == NULL) {
            return USER_ADD_INVALID;
        }
    }
    if (hashmap_get(user_credentials, username) != NULL) {
        return USER_ADD_EXISTS;
    }
    if (user_credentials->size >= MAX_USERS) {
        return USER_ADD_FULL;
    }
    return hashmap_insert(user_credentials, username, password, 0) != 0
        ? USER_ADD_OK : USER_ADD_INVALID;
}

/** true si hay más de un usuario con is_admin=true en la tabla */
static bool
has_other_admin(const char *excluding_username) {
    size_t admins = 0;
    for (size_t i = 0; i < user_credentials->capacity; i++) {
        const static_entry *e = &user_credentials->entries[i];
        if (e->present && e->is_admin && strcmp(e->key, excluding_username) != 0) {
            admins++;
        }
    }
    return admins > 0;
}

enum user_del_result delete_user_credentials(const char *username) {
    if (user_credentials == NULL) {
        return USER_DEL_NOT_FOUND;
    }
    const static_entry *entry = hashmap_get(user_credentials, username);
    if (entry == NULL) {
        return USER_DEL_NOT_FOUND;
    }
    if (entry->is_admin && !has_other_admin(username)) {
        return USER_DEL_LAST_ADMIN;
    }
    hashmap_delete(user_credentials, username);
    return USER_DEL_OK;
}

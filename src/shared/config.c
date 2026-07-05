#include "config.h"

static unsigned timeout_seconds = CONFIG_TIMEOUT_DEFAULT;
static size_t   buf_size_bytes  = CONFIG_BUF_SIZE_DEFAULT;

unsigned
config_get_timeout(void) {
    return timeout_seconds;
}

void
config_set_timeout(unsigned seconds) {
    timeout_seconds = seconds;
}

size_t
config_get_buf_size(void) {
    return buf_size_bytes;
}

void
config_set_buf_size(size_t bytes) {
    buf_size_bytes = bytes;
}

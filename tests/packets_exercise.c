#include "packets_exercise.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "packets.h"

#ifndef SSIZE_MAX
#define SSIZE_MAX LONG_MAX
#endif

static char *copy_with_slack(const uint8_t *data, size_t size, size_t slack)
{
    char *buffer = calloc(1, size + slack);
    if (!buffer) {
        return 0;
    }
    memcpy(buffer, data, size);
    return buffer;
}

void exercise_packets_input(const uint8_t *data, size_t size)
{
    char *host = 0;
    uint16_t port = 0;

    if (!data || size > (size_t)(SSIZE_MAX - 64)) {
        return;
    }

    const char *bytes = (const char *)data;
    size_t split = size / 2;

    (void)is_http(bytes, size);
    (void)is_tls_chello(bytes, size);
    (void)is_tls_shello(bytes, size);
    (void)parse_http(bytes, size, &host, &port);
    host = 0;
    port = 0;
    (void)parse_tls(bytes, size, &host);

    if (split < size) {
        (void)is_http_redirect(bytes, split, bytes + split, size - split);
        (void)neq_tls_sid(bytes, split, bytes + split, size - split);
    }

    char *mutable = copy_with_slack(data, size, 64);
    if (!mutable) {
        return;
    }

    (void)mod_http(mutable, size, MH_HMIX | MH_SPACE);

    memcpy(mutable, data, size);
    (void)part_tls(mutable, size + 64, (ssize_t)size, size > 16 ? 8 : 1);

    memcpy(mutable, data, size);
    randomize_tls(mutable, (ssize_t)size);

    host = 0;
    if (parse_tls(bytes, size, &host) > 0) {
        memcpy(mutable, data, size);
        (void)change_tls_sni("docs.example.test", mutable, (ssize_t)size, (ssize_t)(size + 64));
    }

    free(mutable);
}

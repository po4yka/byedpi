#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packets.h"
#include "oracle_common.h"

static uint16_t read_u16(const char *data, size_t offset)
{
    return ((uint16_t)(uint8_t)data[offset] << 8) | (uint8_t)data[offset + 1];
}


static size_t tls_message_len(const char *data, size_t size)
{
    if (size < 5 || !is_tls_chello(data, size)) {
        return size;
    }
    size_t len = 5 + read_u16(data, 3);
    return len < size ? len : size;
}


static size_t oracle_find_tls_ext_offset(uint16_t type,
        const char *data, size_t size, size_t skip)
{
    if (size <= (skip + 2)) {
        return 0;
    }
    uint16_t ext_len = read_u16(data, skip);
    skip += 2;

    if (ext_len < (size - skip)) {
        size = ext_len + skip;
    }
    while ((skip + 4) < size) {
        uint16_t curr_type = read_u16(data, skip);
        if (curr_type == type) {
            return skip;
        }
        skip += (size_t)read_u16(data, skip + 2) + 4;
    }
    return 0;
}


static size_t oracle_find_ext_block(const char *data, size_t size)
{
    if (size < 44) {
        return 0;
    }
    uint8_t sid_len = (uint8_t)data[43];
    if (size < (44u + sid_len + 2u)) {
        return 0;
    }
    uint16_t cip_len = read_u16(data, 44u + sid_len);
    size_t skip = 44u + sid_len + 2u + cip_len + 2u;
    return skip > size ? 0 : skip;
}


static uint32_t oracle_rand_next(uint32_t *state)
{
    *state = *state * 1103515245u + 12345u;
    return (*state >> 16) & 0x7fffu;
}


static void oracle_fill_rand(char *out, size_t len, uint32_t *state)
{
    for (size_t i = 0; i < len; i++) {
        out[i] = (char)(oracle_rand_next(state) & 0xff);
    }
}


static void oracle_randomize_tls_seeded(char *buffer, size_t size, uint32_t seed)
{
    if (size < 44) {
        return;
    }
    uint8_t sid_len = (uint8_t)buffer[43];
    if (size < (44u + sid_len + 2u)) {
        return;
    }
    oracle_fill_rand(buffer + 11, 32, &seed);
    oracle_fill_rand(buffer + 44, sid_len, &seed);

    size_t skip = oracle_find_ext_block(buffer, size);
    if (!skip) {
        return;
    }
    size_t ks_offs = oracle_find_tls_ext_offset(0x0033, buffer, size, skip);
    if (!ks_offs || ks_offs + 6 >= size) {
        return;
    }
    uint16_t ks_size = read_u16(buffer, ks_offs + 2);
    if (ks_offs + 4u + ks_size > size) {
        return;
    }
    size_t group_offs = ks_offs + 6;
    while (group_offs + 4 < ks_offs + 4u + ks_size) {
        uint16_t group_size = read_u16(buffer, group_offs + 2);
        if (ks_offs + 4u + group_size > size) {
            return;
        }
        oracle_fill_rand(buffer + group_offs + 4, group_size, &seed);
        group_offs += (size_t)group_size + 4u;
    }
}


static void print_mutation_result(int ok, const char *buffer, size_t len, int rc)
{
    printf("{\"ok\":%s,\"rc\":%d,\"len\":%zu,\"hex\":\"",
        ok ? "true" : "false", rc, len);
    oracle_print_hex(stdout, buffer, len);
    puts("\"}");
}


int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <command> <file> [args...]\n", argv[0]);
        return 1;
    }
    const char *cmd = argv[1];
    size_t size = 0;
    char *data = oracle_read_file(argv[2], &size);
    if (!data) {
        perror("oracle_read_file");
        return 1;
    }

    if (!strcmp(cmd, "parse_http")) {
        char *host = 0;
        uint16_t port = 0;
        int len = parse_http(data, size, &host, &port);
        printf("{\"ok\":%s", len > 0 ? "true" : "false");
        if (len > 0) {
            fputs(",\"host\":", stdout);
            oracle_print_json_string(stdout, host, (size_t)len);
            printf(",\"port\":%u", (unsigned)port);
        }
        puts("}");
    }
    else if (!strcmp(cmd, "parse_tls")) {
        char *host = 0;
        int len = parse_tls(data, size, &host);
        printf("{\"ok\":%s", len > 0 ? "true" : "false");
        if (len > 0) {
            fputs(",\"host\":", stdout);
            oracle_print_json_string(stdout, host, (size_t)len);
        }
        puts("}");
    }
    else if (!strcmp(cmd, "is_http_redirect")) {
        if (argc < 4) {
            fprintf(stderr, "expected response file\n");
            free(data);
            return 1;
        }
        size_t resp_size = 0;
        char *resp = oracle_read_file(argv[3], &resp_size);
        if (!resp) {
            perror("oracle_read_file");
            free(data);
            return 1;
        }
        printf("{\"ok\":%s}\n",
            is_http_redirect(data, size, resp, resp_size) ? "true" : "false");
        free(resp);
    }
    else if (!strcmp(cmd, "neq_tls_sid")) {
        if (argc < 4) {
            fprintf(stderr, "expected response file\n");
            free(data);
            return 1;
        }
        size_t resp_size = 0;
        char *resp = oracle_read_file(argv[3], &resp_size);
        if (!resp) {
            perror("oracle_read_file");
            free(data);
            return 1;
        }
        printf("{\"ok\":%s}\n",
            neq_tls_sid(data, size, resp, resp_size) ? "true" : "false");
        free(resp);
    }
    else if (!strcmp(cmd, "mod_http")) {
        if (argc < 4) {
            fprintf(stderr, "expected flags\n");
            free(data);
            return 1;
        }
        int flags = (int)strtol(argv[3], 0, 0);
        char *buffer = malloc(size);
        if (!buffer) {
            free(data);
            return 1;
        }
        memcpy(buffer, data, size);
        int rc = mod_http(buffer, size, flags);
        print_mutation_result(rc == 0, buffer, size, rc);
        free(buffer);
    }
    else if (!strcmp(cmd, "part_tls")) {
        if (argc < 4) {
            fprintf(stderr, "expected split position\n");
            free(data);
            return 1;
        }
        long pos = strtol(argv[3], 0, 0);
        size_t slack = argc > 4 ? (size_t)strtoul(argv[4], 0, 0) : 64;
        char *buffer = calloc(1, size + slack);
        if (!buffer) {
            free(data);
            return 1;
        }
        memcpy(buffer, data, size);
        int rc = part_tls(buffer, size + slack, (ssize_t)size, pos);
        size_t out_len = rc > 0 ? size + (size_t)rc : size;
        print_mutation_result(rc >= 0, buffer, out_len, rc);
        free(buffer);
    }
    else if (!strcmp(cmd, "change_tls_sni")) {
        if (argc < 4) {
            fprintf(stderr, "expected replacement host\n");
            free(data);
            return 1;
        }
        size_t cap = argc > 4 ? (size_t)strtoul(argv[4], 0, 0) : size + 64;
        char *buffer = calloc(1, cap);
        if (!buffer) {
            free(data);
            return 1;
        }
        memcpy(buffer, data, size);
        int rc = change_tls_sni(argv[3], buffer, (ssize_t)size, (ssize_t)cap);
        size_t out_len = tls_message_len(buffer, cap);
        print_mutation_result(rc == 0, buffer, out_len, rc);
        free(buffer);
    }
    else if (!strcmp(cmd, "randomize_tls")) {
        unsigned int seed = argc > 3 ? (unsigned int)strtoul(argv[3], 0, 0) : 1;
        srand(seed);
        char *buffer = malloc(size);
        if (!buffer) {
            free(data);
            return 1;
        }
        memcpy(buffer, data, size);
        randomize_tls(buffer, (ssize_t)size);
        print_mutation_result(1, buffer, size, 0);
        free(buffer);
    }
    else if (!strcmp(cmd, "randomize_tls_seeded")) {
        uint32_t seed = argc > 3 ? (uint32_t)strtoul(argv[3], 0, 0) : 1u;
        char *buffer = malloc(size);
        if (!buffer) {
            free(data);
            return 1;
        }
        memcpy(buffer, data, size);
        oracle_randomize_tls_seeded(buffer, size, seed);
        print_mutation_result(1, buffer, size, 0);
        free(buffer);
    }
    else {
        fprintf(stderr, "unknown command: %s\n", cmd);
        free(data);
        return 1;
    }

    free(data);
    return 0;
}

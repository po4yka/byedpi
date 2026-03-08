#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packets.h"
#include "packets_exercise.h"

#define EXPECT(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr); \
        return 1; \
    } \
} while (0)

static const char expected_host[] = "www.wikipedia.org";

static uint8_t *load_seed(const char *dir, const char *name, size_t *size)
{
    size_t path_len = strlen(dir) + strlen(name) + 2;
    char *path = malloc(path_len);
    if (!path) {
        return 0;
    }
    snprintf(path, path_len, "%s/%s", dir, name);

    FILE *file = fopen(path, "rb");
    free(path);
    if (!file) {
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 0;
    }
    long len = ftell(file);
    if (len < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    uint8_t *data = malloc((size_t)len);
    if (!data) {
        fclose(file);
        return 0;
    }
    if (fread(data, 1, (size_t)len, file) != (size_t)len) {
        free(data);
        fclose(file);
        return 0;
    }
    fclose(file);
    *size = (size_t)len;
    return data;
}

static int expect_host_value(const char *host, int len, const char *expected)
{
    size_t expected_len = strlen(expected);
    EXPECT(len == (int)expected_len,
        "unexpected host length: got=%d want=%zu", len, expected_len);
    EXPECT(memcmp(host, expected, expected_len) == 0,
        "unexpected host value");
    return 0;
}

static int test_http_request(const char *dir)
{
    size_t size = 0;
    uint8_t *data = load_seed(dir, "http_request.bin", &size);
    EXPECT(data, "failed to load http request corpus");

    exercise_packets_input(data, size);
    EXPECT(is_http((const char *)data, size), "expected HTTP request");

    char *host = 0;
    uint16_t port = 0;
    int len = parse_http((const char *)data, size, &host, &port);
    EXPECT(len > 0, "failed to parse HTTP request");
    EXPECT(expect_host_value(host, len, expected_host) == 0, "unexpected parsed host");
    EXPECT(port == 80, "unexpected parsed HTTP port: %u", (unsigned)port);

    char *mutable = malloc(size);
    EXPECT(mutable, "failed to allocate HTTP mutation buffer");
    memcpy(mutable, data, size);
    EXPECT(mod_http(mutable, size, MH_HMIX | MH_SPACE) == 0,
        "failed to modify HTTP request");
    host = 0;
    port = 0;
    len = parse_http(mutable, size, &host, &port);
    EXPECT(len > 0, "failed to parse modified HTTP request");
    EXPECT(expect_host_value(host, len, expected_host) == 0,
        "unexpected host after HTTP mutation");
    EXPECT(port == 80, "unexpected port after HTTP mutation: %u", (unsigned)port);

    free(mutable);
    free(data);
    return 0;
}

static int test_http_redirect(const char *dir)
{
    size_t req_size = 0, resp_size = 0;
    uint8_t *req = load_seed(dir, "http_request.bin", &req_size);
    uint8_t *resp = load_seed(dir, "http_redirect_response.bin", &resp_size);
    EXPECT(req && resp, "failed to load HTTP redirect corpus");

    EXPECT(is_http_redirect((const char *)req, req_size, (const char *)resp, resp_size),
        "expected redirect detection");

    free(req);
    free(resp);
    return 0;
}

static int test_tls_request(const char *dir)
{
    size_t size = 0;
    uint8_t *data = load_seed(dir, "tls_client_hello.bin", &size);
    EXPECT(data, "failed to load TLS client hello corpus");

    exercise_packets_input(data, size);
    EXPECT(is_tls_chello((const char *)data, size), "expected TLS client hello");

    char *host = 0;
    int len = parse_tls((const char *)data, size, &host);
    EXPECT(len > 0, "failed to parse TLS SNI");
    EXPECT(expect_host_value(host, len, expected_host) == 0, "unexpected TLS host");

    char *mutable = calloc(1, size + 16);
    EXPECT(mutable, "failed to allocate TLS split buffer");
    memcpy(mutable, data, size);
    EXPECT(part_tls(mutable, size + 16, (ssize_t)size, 32) == 5,
        "failed to split TLS record");

    memcpy(mutable, data, size);
    srand(1);
    randomize_tls(mutable, (ssize_t)size);
    host = 0;
    len = parse_tls(mutable, size, &host);
    EXPECT(len > 0, "failed to parse randomized TLS payload");
    EXPECT(expect_host_value(host, len, expected_host) == 0,
        "unexpected TLS host after randomization");

    free(mutable);
    free(data);
    return 0;
}

static int test_tls_sid_mismatch(const char *dir)
{
    size_t req_size = 0, resp_size = 0;
    uint8_t *req = load_seed(dir, "tls_client_hello.bin", &req_size);
    uint8_t *resp = load_seed(dir, "tls_server_hello_like.bin", &resp_size);
    EXPECT(req && resp, "failed to load TLS SID corpus");

    EXPECT(is_tls_shello((const char *)resp, resp_size),
        "expected TLS server hello-like response");
    EXPECT(neq_tls_sid((const char *)req, req_size, (const char *)resp, resp_size),
        "expected TLS SID mismatch");

    free(req);
    free(resp);
    return 0;
}

static int test_tls_sni_change_with_ech_expand(const char *dir)
{
    static const char new_host[] = "docs.example.test";

    size_t size = 0;
    uint8_t *data = load_seed(dir, "tls_client_hello_ech.bin", &size);
    EXPECT(data, "failed to load TLS ECH corpus");

    size_t capacity = size + 32;
    char *mutable = calloc(1, capacity);
    EXPECT(mutable, "failed to allocate TLS ECH expansion buffer");
    memcpy(mutable, data, size);

    EXPECT(change_tls_sni(new_host, mutable, (ssize_t)size, (ssize_t)capacity) == 0,
        "failed to change TLS SNI with ECH growth");

    char *host = 0;
    int len = parse_tls(mutable, capacity, &host);
    EXPECT(len > 0, "failed to parse grown TLS ECH payload");
    EXPECT(expect_host_value(host, len, new_host) == 0,
        "unexpected host after TLS ECH growth");

    free(mutable);
    free(data);
    return 0;
}

static int test_tls_sni_change_with_ech_shrink(const char *dir)
{
    static const char new_host[] = "a.docs.example.test";

    size_t size = 0;
    uint8_t *data = load_seed(dir, "tls_client_hello_ech.bin", &size);
    EXPECT(data, "failed to load TLS ECH shrink corpus");

    char *mutable = malloc(size);
    EXPECT(mutable, "failed to allocate TLS ECH shrink buffer");
    memcpy(mutable, data, size);

    EXPECT(change_tls_sni(new_host, mutable, (ssize_t)size, (ssize_t)size) == 0,
        "failed to change TLS SNI with ECH shrink");

    char *host = 0;
    int len = parse_tls(mutable, size, &host);
    EXPECT(len > 0, "failed to parse shrunken TLS ECH payload");
    EXPECT(expect_host_value(host, len, new_host) == 0,
        "unexpected host after TLS ECH shrink");

    free(mutable);
    free(data);
    return 0;
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "tests/corpus/packets";

    EXPECT(test_http_request(dir) == 0, "HTTP request regression failed");
    EXPECT(test_http_redirect(dir) == 0, "HTTP redirect regression failed");
    EXPECT(test_tls_request(dir) == 0, "TLS request regression failed");
    EXPECT(test_tls_sid_mismatch(dir) == 0, "TLS SID regression failed");
    EXPECT(test_tls_sni_change_with_ech_expand(dir) == 0,
        "TLS ECH growth regression failed");
    EXPECT(test_tls_sni_change_with_ech_shrink(dir) == 0,
        "TLS ECH shrink regression failed");

    puts("packets tests passed");
    return 0;
}

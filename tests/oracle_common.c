#include "oracle_common.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


char *oracle_read_file(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
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
    char *data = malloc((size_t)len);
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


void oracle_print_json_string(FILE *out, const char *data, size_t len)
{
    fputc('"', out);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        switch (c) {
        case '\\':
        case '"':
            fprintf(out, "\\%c", c);
            break;
        case '\b':
            fputs("\\b", out);
            break;
        case '\f':
            fputs("\\f", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (c < 0x20) {
                fprintf(out, "\\u%04x", c);
            } else {
                fputc(c, out);
            }
        }
    }
    fputc('"', out);
}


void oracle_print_hex(FILE *out, const char *data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        fputc(hex[c >> 4], out);
        fputc(hex[c & 0x0f], out);
    }
}


void oracle_print_addr_json(FILE *out, const union sockaddr_u *addr)
{
    char buffer[INET6_ADDRSTRLEN];
    if (addr->sa.sa_family != AF_INET && addr->sa.sa_family != AF_INET6) {
        fputs("{\"family\":\"none\",\"addr\":null,\"port\":0}", out);
        return;
    }
    const char *family = addr->sa.sa_family == AF_INET6 ? "ipv6" : "ipv4";
    const void *raw = addr->sa.sa_family == AF_INET6
        ? (const void *)&addr->in6.sin6_addr
        : (const void *)&addr->in.sin_addr;
    inet_ntop(addr->sa.sa_family, raw, buffer, sizeof(buffer));
    fprintf(out, "{\"family\":\"%s\",\"addr\":", family);
    oracle_print_json_string(out, buffer, strlen(buffer));
    fprintf(out, ",\"port\":%u}", (unsigned)ntohs(addr->in.sin_port));
}

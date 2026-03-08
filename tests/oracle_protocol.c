#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proxy.h"
#include "oracle_common.h"

static void print_result(int ok, int rc, const union sockaddr_u *addr)
{
    printf("{\"ok\":%s,\"rc\":%d", ok ? "true" : "false", rc);
    if (ok) {
        fputs(",\"addr\":", stdout);
        oracle_print_addr_json(stdout, addr);
    }
    puts("}");
}


int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <command> <file> [stream|dgram]\n", argv[0]);
        return 1;
    }
    size_t size = 0;
    char *data = oracle_read_file(argv[2], &size);
    if (!data) {
        perror("oracle_read_file");
        return 1;
    }
    union sockaddr_u addr = { 0 };
    int rc = -1;

    if (!strcmp(argv[1], "socks4")) {
        rc = s4_get_addr(data, size, &addr);
        print_result(rc == 0, rc, &addr);
    }
    else if (!strcmp(argv[1], "socks5")) {
        int type = argc > 3 && !strcmp(argv[3], "dgram") ? SOCK_DGRAM : SOCK_STREAM;
        rc = s5_get_addr(data, size, &addr, type);
        print_result(rc >= 0, rc, &addr);
    }
    else if (!strcmp(argv[1], "http_connect")) {
        rc = http_get_addr(data, size, &addr);
        print_result(rc == 0, rc, &addr);
    }
    else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        free(data);
        return 1;
    }

    free(data);
    return 0;
}

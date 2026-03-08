#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"
#include "mpool.h"
#include "oracle_common.h"

static int first_actionable_group(const struct desync_params *dp)
{
    int idx = 0;
    for (; dp; dp = dp->next, idx++) {
        if (dp->parts_n || dp->tlsrec_n || dp->mod_http || dp->tlsminor_set
                || dp->fake_data.data || dp->fake_sni_count || dp->fake_offset.m
                || dp->udp_fake_count || dp->detect || dp->hosts || dp->ipset
                || dp->pf[0] || dp->ext_socks.in.sin_port) {
            return idx;
        }
    }
    return 0;
}


static void print_part_array(const struct part *parts, int count)
{
    putchar('[');
    for (int i = 0; i < count; i++) {
        if (i) {
            putchar(',');
        }
        printf("{\"mode\":%d,\"flag\":%d,\"pos\":%ld,\"r\":%d,\"s\":%d}",
            parts[i].m, parts[i].flag, parts[i].pos, parts[i].r, parts[i].s);
    }
    putchar(']');
}


static void print_string_array(const char **items, int count)
{
    putchar('[');
    for (int i = 0; i < count; i++) {
        if (i) {
            putchar(',');
        }
        oracle_print_json_string(stdout, items[i], strlen(items[i]));
    }
    putchar(']');
}


static void print_group_json(const struct desync_params *dp)
{
    printf("{\"id\":%d,\"detect\":%d,\"proto\":%d,\"ttl\":%d,"
            "\"md5sig\":%s,\"udp_fake_count\":%d,\"fake_mod\":%d,"
            "\"fake_tls_size\":%d,\"drop_sack\":%s,\"mod_http\":%d,"
            "\"tlsminor\":%u,\"tlsminor_set\":%s,\"cache_ttl\":%ld,"
            "\"cache_file\":",
        dp->id, dp->detect, dp->proto, dp->ttl,
        dp->md5sig ? "true" : "false", dp->udp_fake_count, dp->fake_mod,
        dp->fake_tls_size, dp->drop_sack ? "true" : "false",
        dp->mod_http, (unsigned)dp->tlsminor,
        dp->tlsminor_set ? "true" : "false", dp->cache_ttl);
    if (dp->cache_file) {
        oracle_print_json_string(stdout, dp->cache_file, strlen(dp->cache_file));
    } else {
        fputs("null", stdout);
    }
    fputs(",\"rounds\":[", stdout);
    printf("%d,%d],\"pf\":[%u,%u],\"hosts_count\":%zu,\"ipset_count\":%zu,"
        "\"parts\":", dp->rounds[0], dp->rounds[1],
        (unsigned)ntohs(dp->pf[0]), (unsigned)ntohs(dp->pf[1]),
        dp->hosts ? dp->hosts->count : 0, dp->ipset ? dp->ipset->count : 0);
    print_part_array(dp->parts, dp->parts_n);
    fputs(",\"tlsrec\":", stdout);
    print_part_array(dp->tlsrec, dp->tlsrec_n);
    fputs(",\"fake_sni_list\":", stdout);
    print_string_array(dp->fake_sni_list, dp->fake_sni_count);
    fputs(",\"ext_socks\":", stdout);
    oracle_print_addr_json(stdout, &dp->ext_socks);
    putchar('}');
}


static void print_params_json(void)
{
    char listen_ip[INET6_ADDRSTRLEN];
    char bind_ip[INET6_ADDRSTRLEN];
    const void *listen_raw = params.laddr.sa.sa_family == AF_INET6
        ? (const void *)&params.laddr.in6.sin6_addr
        : (const void *)&params.laddr.in.sin_addr;
    const void *bind_raw = params.baddr.sa.sa_family == AF_INET6
        ? (const void *)&params.baddr.in6.sin6_addr
        : (const void *)&params.baddr.in.sin_addr;
    inet_ntop(params.laddr.sa.sa_family, listen_raw, listen_ip, sizeof(listen_ip));
    inet_ntop(params.baddr.sa.sa_family, bind_raw, bind_ip, sizeof(bind_ip));

    printf("{\"listen_ip\":");
    oracle_print_json_string(stdout, listen_ip, strlen(listen_ip));
    printf(",\"listen_port\":%u,\"bind_ip\":", (unsigned)ntohs(params.laddr.in.sin_port));
    oracle_print_json_string(stdout, bind_ip, strlen(bind_ip));
    printf(",\"resolve\":%s,\"udp\":%s,\"ipv6\":%s,\"transparent\":%s,"
            "\"http_connect\":%s,\"shadowsocks\":%s,\"delay_conn\":%s,"
            "\"bfsize\":%zu,\"max_open\":%d,\"cache_ttl\":%ld,\"debug\":%d,"
            "\"protect_path\":",
        params.resolve ? "true" : "false",
        params.udp ? "true" : "false",
        params.ipv6 ? "true" : "false",
        params.transparent ? "true" : "false",
        params.http_connect ? "true" : "false",
        params.shadowsocks ? "true" : "false",
        params.delay_conn ? "true" : "false",
        params.bfsize, params.max_open, params.cache_ttl, params.debug);
    if (params.protect_path) {
        oracle_print_json_string(stdout, params.protect_path, strlen(params.protect_path));
    } else {
        fputs("null", stdout);
    }
    printf(",\"dp_n\":%d,\"actionable_group\":%d,\"groups\":[",
        params.dp_n, first_actionable_group(params.dp));
    for (struct desync_params *dp = params.dp; dp; dp = dp->next) {
        if (dp != params.dp) {
            putchar(',');
        }
        print_group_json(dp);
    }
    puts("]}");
}


static int run_parse_args(int argc, char **argv)
{
    apply_startup_env();

    int parse_argc = argc - 1;
    char **parse_argv = calloc((size_t)parse_argc + 2, sizeof(char *));
    if (!parse_argv) {
        return 1;
    }
    char **base_argv = parse_argv;
    parse_argv[0] = "ciadpi";
    for (int i = 2; i < argc; i++) {
        parse_argv[i - 1] = argv[i];
    }
    parse_argc = argc - 1;
    char *line = build_env_argv(&parse_argc, &parse_argv);
    if (line) {
        free(base_argv);
    }

    int rc = parse_args(parse_argc, parse_argv);
    if (rc == 0) {
        print_params_json();
    } else {
        printf("{\"ok\":false,\"rc\":%d}\n", rc);
    }
    clear_params(line, line ? parse_argv : 0);
    if (!line) {
        free(base_argv);
    }
    return rc == 0 ? 0 : 1;
}


static int run_hosts_match(const char *spec, const char *host)
{
    ssize_t size = 0;
    char *data = ftob(spec, &size);
    if (!data) {
        return 1;
    }
    struct mphdr *hdr = mem_pool(MF_STATIC, CMP_HOST);
    if (!hdr) {
        free(data);
        return 1;
    }
    int rc = parse_hosts(hdr, data, (size_t)size);
    struct elem *match = rc == 0 ? mem_get(hdr, host, (int)strlen(host)) : 0;
    printf("{\"ok\":%s,\"matched\":%s}\n",
        rc == 0 ? "true" : "false",
        match && match->len <= (int)strlen(host) ? "true" : "false");
    mem_destroy(hdr);
    free(data);
    return rc == 0 ? 0 : 1;
}


static int run_ipset_match(const char *spec, const char *ip)
{
    ssize_t size = 0;
    char *data = ftob(spec, &size);
    if (!data) {
        return 1;
    }
    struct mphdr *hdr = mem_pool(0, CMP_BITS);
    if (!hdr) {
        free(data);
        return 1;
    }
    int rc = parse_ipset(hdr, data, (size_t)size);
    char raw[sizeof(struct in6_addr)];
    int bits = 0;
    if (inet_pton(AF_INET, ip, raw) > 0) {
        bits = 32;
    }
    else if (inet_pton(AF_INET6, ip, raw) > 0) {
        bits = 128;
    }
    struct elem *match = rc == 0 && bits ? mem_get(hdr, raw, bits) : 0;
    printf("{\"ok\":%s,\"matched\":%s}\n",
        rc == 0 ? "true" : "false", match ? "true" : "false");
    mem_destroy(hdr);
    free(data);
    return rc == 0 ? 0 : 1;
}


static int run_cache_roundtrip(const char *path)
{
    FILE *in = fopen(path, "r");
    if (!in) {
        perror("fopen");
        return 1;
    }
    struct mphdr *hdr = mem_pool(MF_EXTRA, CMP_BITS);
    if (!hdr) {
        fclose(in);
        return 1;
    }
    struct desync_params dp = { 0 };
    load_cache(hdr, in, &dp);
    fclose(in);
    dump_cache(hdr, stdout, &dp);
    mem_destroy(hdr);
    return 0;
}


int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }
    if (!strcmp(argv[1], "parse_args")) {
        return run_parse_args(argc, argv);
    }
    if (!strcmp(argv[1], "hosts_match") && argc >= 4) {
        return run_hosts_match(argv[2], argv[3]);
    }
    if (!strcmp(argv[1], "ipset_match") && argc >= 4) {
        return run_ipset_match(argv[2], argv[3]);
    }
    if (!strcmp(argv[1], "cache_roundtrip") && argc >= 3) {
        return run_cache_roundtrip(argv[2]);
    }
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
}

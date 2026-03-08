#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"
#include "desync.h"
#include "oracle_common.h"

static struct desync_params *find_target_group(void)
{
    for (struct desync_params *dp = params.dp; dp; dp = dp->next) {
        if (dp->parts_n || dp->tlsrec_n || dp->mod_http || dp->tlsminor_set
                || dp->fake_data.data || dp->fake_sni_count || dp->fake_offset.m
                || dp->udp_fake_count || dp->detect) {
            return dp;
        }
    }
    return params.dp;
}


int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <packet-file> <seed> [ciadpi args...]\n", argv[0]);
        return 1;
    }
    size_t input_len = 0;
    char *input = oracle_read_file(argv[1], &input_len);
    if (!input) {
        perror("oracle_read_file");
        return 1;
    }
    unsigned int seed = (unsigned int)strtoul(argv[2], 0, 0);

    int parse_argc = argc - 2;
    char **parse_argv = calloc((size_t)parse_argc + 1, sizeof(char *));
    if (!parse_argv) {
        free(input);
        return 1;
    }
    parse_argv[0] = "ciadpi";
    for (int i = 3; i < argc; i++) {
        parse_argv[i - 2] = argv[i];
    }

    int rc = parse_args(parse_argc, parse_argv);
    if (rc != 0) {
        printf("{\"ok\":false,\"rc\":%d}\n", rc);
        free(parse_argv);
        free(input);
        return 1;
    }

    struct desync_params *dp = find_target_group();
    size_t buffer_size = input_len + 64 + (size_t)dp->tlsrec_n * 5;
    char *output = calloc(1, buffer_size);
    struct desync_plan_step *steps = calloc((size_t)dp->parts_n + 8, sizeof(*steps));
    if (!output || !steps) {
        clear_params(0, 0);
        free(parse_argv);
        free(input);
        free(output);
        free(steps);
        return 1;
    }

    struct desync_plan_result result = { 0 };
    rc = desync_plan_buffer(input, input_len, buffer_size, dp, seed,
        output, steps, (size_t)dp->parts_n + 8, &result);
    printf("{\"ok\":%s,\"rc\":%d,\"tampered_len\":%zd,\"proto_type\":%d,"
            "\"host_pos\":%d,\"host_len\":%d,\"steps\":[",
        rc == 0 ? "true" : "false", rc, result.tampered_len,
        result.info.type, result.info.host_pos, result.info.host_len);
    for (int i = 0; i < result.step_count; i++) {
        if (i) {
            putchar(',');
        }
        printf("{\"mode\":%d,\"start\":%ld,\"end\":%ld}",
            steps[i].mode, steps[i].start, steps[i].end);
    }
    fputs("],\"tampered_hex\":\"", stdout);
    oracle_print_hex(stdout, output, (size_t)result.tampered_len);
    puts("\"}");

    clear_params(0, 0);
    free(parse_argv);
    free(input);
    free(output);
    free(steps);
    return rc == 0 ? 0 : 1;
}

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


static int print_plan(const char *input, size_t input_len,
        unsigned int seed, struct desync_params *dp)
{
    size_t buffer_size = input_len + 64 + (size_t)dp->tlsrec_n * 5;
    char *output = calloc(1, buffer_size);
    struct desync_plan_step *steps = calloc((size_t)dp->parts_n + 8, sizeof(*steps));
    if (!output || !steps) {
        free(output);
        free(steps);
        return 1;
    }
    struct desync_plan_result result = { 0 };
    int rc = desync_plan_buffer(input, input_len, buffer_size, dp, seed,
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
    free(output);
    free(steps);
    return rc == 0 ? 0 : 1;
}

static int print_fake(const char *input, size_t input_len,
        unsigned int seed, struct desync_params *dp)
{
    size_t output_size = input_len + 128;
    char *output = calloc(1, output_size);
    if (!output) {
        return 1;
    }
    struct desync_fake_result result = { 0 };
    int rc = desync_build_fake_packet(input, input_len, dp, seed,
        output, output_size, &result);
    printf("{\"ok\":%s,\"rc\":%d,\"fake_len\":%zd,\"fake_offset\":%zd,"
            "\"proto_type\":%d,\"host_pos\":%d,\"host_len\":%d,\"fake_hex\":\"",
        rc == 0 ? "true" : "false", rc, result.fake_len, result.fake_offset,
        result.info.type, result.info.host_pos, result.info.host_len);
    oracle_print_hex(stdout, output, (size_t)(rc == 0 ? result.fake_len : 0));
    puts("\"}");
    free(output);
    return rc == 0 ? 0 : 1;
}


int main(int argc, char **argv)
{
    const char *command = "plan";
    int input_idx = 1;
    int seed_idx = 2;
    int args_idx = 3;

    if (argc >= 2 && (!strcmp(argv[1], "plan") || !strcmp(argv[1], "fake"))) {
        command = argv[1];
        input_idx = 2;
        seed_idx = 3;
        args_idx = 4;
    }
    if (argc <= seed_idx) {
        fprintf(stderr, "usage: %s [plan|fake] <packet-file> <seed> [ciadpi args...]\n", argv[0]);
        return 1;
    }
    size_t input_len = 0;
    char *input = oracle_read_file(argv[input_idx], &input_len);
    if (!input) {
        perror("oracle_read_file");
        return 1;
    }
    unsigned int seed = (unsigned int)strtoul(argv[seed_idx], 0, 0);

    int parse_argc = argc - seed_idx;
    char **parse_argv = calloc((size_t)parse_argc + 1, sizeof(char *));
    if (!parse_argv) {
        free(input);
        return 1;
    }
    parse_argv[0] = "ciadpi";
    for (int i = args_idx; i < argc; i++) {
        parse_argv[i - seed_idx] = argv[i];
    }

    int rc = parse_args(parse_argc, parse_argv);
    if (rc != 0) {
        printf("{\"ok\":false,\"rc\":%d}\n", rc);
        free(parse_argv);
        free(input);
        return 1;
    }

    struct desync_params *dp = find_target_group();
    if (!strcmp(command, "fake")) {
        rc = print_fake(input, input_len, seed, dp);
    } else {
        rc = print_plan(input, input_len, seed, dp);
    }

    clear_params(0, 0);
    free(parse_argv);
    free(input);
    return rc;
}

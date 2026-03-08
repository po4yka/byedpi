#ifndef APP_H
#define APP_H

#include <stddef.h>

#include "params.h"

char *ftob(const char *str, ssize_t *sl);

int parse_hosts(struct mphdr *hdr, char *buffer, size_t size);

int parse_ipset(struct mphdr *hdr, char *buffer, size_t size);

char *build_env_argv(int *argc, char ***argv);

void apply_startup_env(void);

int init(void);

int parse_args(int argc, char **argv);

void clear_params(char *line, char **argv);

void dump_all_cache(void);

#endif

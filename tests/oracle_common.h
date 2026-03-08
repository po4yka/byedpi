#ifndef TESTS_ORACLE_COMMON_H
#define TESTS_ORACLE_COMMON_H

#include <stdio.h>
#include <stddef.h>

#include "params.h"

char *oracle_read_file(const char *path, size_t *size);

void oracle_print_json_string(FILE *out, const char *data, size_t len);

void oracle_print_hex(FILE *out, const char *data, size_t len);

void oracle_print_addr_json(FILE *out, const union sockaddr_u *addr);

#endif

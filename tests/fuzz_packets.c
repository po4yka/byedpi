#include <stddef.h>
#include <stdint.h>

#include "packets_exercise.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    exercise_packets_input(data, size);
    return 0;
}

#ifdef TEST_STANDALONE_FUZZ

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *load_file(const char *path, size_t *size)
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

static void mutate(uint8_t *data, size_t size)
{
    if (!size) {
        return;
    }
    int rounds = 1 + (rand() % 8);
    for (int i = 0; i < rounds; i++) {
        size_t index = (size_t)(rand() % (int)size);
        data[index] ^= (uint8_t)rand();
        if (size > 1 && (rand() & 1)) {
            size_t other = (size_t)(rand() % (int)size);
            uint8_t tmp = data[index];
            data[index] = data[other];
            data[other] = tmp;
        }
    }
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "tests/corpus/packets";
    DIR *root = opendir(dir);
    if (!root) {
        perror("opendir");
        return 1;
    }

    srand(1);
    int files = 0;
    struct dirent *entry = 0;
    while ((entry = readdir(root))) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        size_t path_len = strlen(dir) + strlen(entry->d_name) + 2;
        char *path = malloc(path_len);
        if (!path) {
            closedir(root);
            return 1;
        }
        snprintf(path, path_len, "%s/%s", dir, entry->d_name);

        size_t size = 0;
        uint8_t *seed = load_file(path, &size);
        free(path);
        if (!seed) {
            closedir(root);
            return 1;
        }

        LLVMFuzzerTestOneInput(seed, size);
        for (int i = 0; i < 512; i++) {
            uint8_t *mutant = malloc(size);
            if (!mutant) {
                free(seed);
                closedir(root);
                return 1;
            }
            memcpy(mutant, seed, size);
            mutate(mutant, size);
            LLVMFuzzerTestOneInput(mutant, size);
            free(mutant);
        }

        free(seed);
        files++;
    }

    closedir(root);
    if (!files) {
        fprintf(stderr, "no fuzz corpus files found in %s\n", dir);
        return 1;
    }

    puts("packets fuzz smoke passed");
    return 0;
}

#endif

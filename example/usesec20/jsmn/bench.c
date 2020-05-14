#include "jsmn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TOKENS 1000 * 1024
jsmntok_t t[MAX_TOKENS];

#define MAX_DATA 500 * 1024 * 1024
static char data[MAX_DATA];

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: bench <input file name>\n");
        return 1;
    }

    // fuzzers usually prefer to get input from a file
    FILE *fp;
    if (!(fp = fopen(argv[1], "r"))) {
        printf("Unable to open %s for reading\n", argv[1]);
        return 1;
    }

    size_t data_len;
    fseek(fp, 0, SEEK_END);
    data_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // skip super long inputs
    if (data_len >= MAX_DATA) {
        return 0;
    }

    fread(data, 1, data_len, fp);
    fclose(fp);

    int i;
    int r;
    jsmn_parser p;

    for (int j = 0; j < 100; j++) {
        jsmn_init(&p);
        r = jsmn_parse(&p, data, data_len, t,
                       sizeof(t) / sizeof(t[0]));
        if (r < 0 || r >= MAX_TOKENS) {
            printf("Failed to parse JSON: %d\n", r);
            return 1;
        }

        /* Assume the top-level element is an object */
        if (r < 1 || t[0].type != JSMN_OBJECT) {
            printf("Object expected\n");
            return 1;
        }
    }

  return EXIT_SUCCESS;
}
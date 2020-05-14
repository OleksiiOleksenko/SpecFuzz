#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <yaml.h>

void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    yaml_parser_t parser;
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser, data, size);

    int done = 0;
    while (!done) {
        yaml_event_t event;
        if (!yaml_parser_parse(&parser, &event)) {
            break;
        }
        done = (event.type == YAML_STREAM_END_EVENT);
        yaml_event_delete(&event);
    }
    yaml_parser_delete(&parser);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Exactly one argument is expected.\n");
        exit(EXIT_FAILURE);v
    }

    FILE *f = fopen(argv[1], "r");
    if (!f) {
        fprintf(stderr, "Failed to open input file.");
        exit(EXIT_FAILURE);
    }

    size_t max_len = 1 << 20;
    unsigned char *tmp = (unsigned char *) malloc(max_len);
    size_t len = fread(tmp, 1, max_len, f);
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "Failed read input file.");
        exit(EXIT_FAILURE);
    }
    /* Make data after the end "inaccessible". */
    unsigned char *data = (unsigned char *) malloc(len);
    memcpy(data, tmp, len);
    free(tmp);

    LLVMFuzzerTestOneInput(data, len);
    free(data);
    exit(EXIT_SUCCESS);
}

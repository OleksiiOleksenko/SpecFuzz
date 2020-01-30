#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

extern size_t array1_size, array2_size;
extern uint8_t temp, array2[], array1[];

void victim_function(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x] * 512];
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("USAGE: %s <input_file>\n", argv[0]);
        exit(1);
    }

    FILE *f = fopen(argv[1], "r");
    if (!f) {
        fprintf(stderr, "Failed to open input file.");
        exit(1);
    }

    char value[1024];
    fscanf(f, " %1023s", value);
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "Failed read input file.");
        exit(1);
    }

    int index = atoi(value);
    victim_function(index);
    printf("r = %d\n", temp);
    return 0;
}

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
        printf("USAGE: %s <index>\n", argv[0]);
        exit(1);
    }

    int index = atoi(argv[1]);
    victim_function(index);
    printf("r = %d\n", temp);
    return 0;
}

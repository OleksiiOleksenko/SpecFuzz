#include <stdlib.h>
#include <stdio.h>

int array_before[] = {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
int array[] = {3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
int array_next[] = {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
int temp;

int main(int argc, char **argv) {
    int index = atoi(argv[1]);
    if (index < 10) {
        temp &= array[index];
    } else {
        temp = 0;
    }
    printf("r = %d\n", temp);
    return 0;
}

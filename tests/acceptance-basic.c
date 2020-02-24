#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>

int array_before[] = {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
int array[] = {3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
int array_next[] = {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
int temp;
char two_pages[2 * 4096] __attribute__((aligned (4096)));

int main(int argc, char **argv) {
    int index = atoi(argv[1]);
    void *invalid_page = &two_pages[4096];
    munmap(invalid_page, 4096);
    //printf("invalid range: %p - %p ; pointer %p\n",
    //       invalid_page,
    //       invalid_page + 4096,
    //       &two_pages[index]);

    if (index < 10) {
        temp &= array[index];
        temp += two_pages[index];
    } else {
        temp = 0;
    }
    printf("r = %d\n", temp);
    return 0;
}

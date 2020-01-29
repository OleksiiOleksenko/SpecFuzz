#include <stdio.h>

extern int test();

int main(int argc, const char *argv[]) {
    int result = test();
    return result;
}



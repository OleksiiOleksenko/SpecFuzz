#include <stdlib.h>

int my_switch(int a) {
    switch (a) {
        case 0:
            a = 0;
            break;
        case 1:
            a = 3;
            break;
        case 2:
            a = 5;
            break;
        case 3:
            a = 7;
            break;
        case 4:
            a = 11;
            break;
        case 5:
            a = 13;
            break;
        case 6:
            a = 17;
            break;
        default:
            a = 19;
            break;
    }
    return a;
}

int main(int argc, char **argv) {
    int a = atoi(argv[1]);
    return my_switch(a);
}
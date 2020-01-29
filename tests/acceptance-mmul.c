//===------------------------------------------------------------------------===//
/// \file
/// A tiny acceptance test to ensure that instrumentation does not do
/// major state corruptions
///
/// Based on simple matrix multiplication
//===------------------------------------------------------------------------===//

#include <stdio.h>

int matA[2][2] = {0, 1, 2, 3};
int matB[2][2] = {4, 5, 6, 7};
int matC[2][2]; // 6 7 26 31

__attribute__((noinline))
void multiply(int i, int j, int N) {
    int k;
    for (k = 0; k < N; k++) {
        matC[i][j] += matA[i][k] * matB[k][j];
    }
}

__attribute__((noinline))
int sum() {
    int total = 0;
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            total += matC[i][j];
        }
    }
    return total;
}

int main() {
    int i, j;

    for (i = 0; i < 2; i++) {
        for (j = 0; j < 2; j++) {
            matC[i][j] = 0;
            multiply(i, j, 2);
        }
    }
    printf("%d\n", sum());
    return 0;
}
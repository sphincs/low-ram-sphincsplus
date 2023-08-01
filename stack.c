#include "stack.h"

#define N 10000

void init_stack(void) {
    unsigned char array[N];
    for (int i=0; i<N; i++) array[i] = 'x';
}

unsigned measure_stack(void) {
    unsigned char array[N];
    int i;
    for (i=0; i<N; i++) if (array[i] != 'x') break;

    return N-i;
}

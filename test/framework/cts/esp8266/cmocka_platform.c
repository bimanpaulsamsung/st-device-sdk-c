#include <stdlib.h>
#include <stdio.h>

void (*signal(int sig, void (*func)(int)))(int) {
    return NULL;
}
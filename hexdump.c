/****************************************************************************
 * hexhump.c
 * Copyright (c) 2016, Greg Johnson, Gnu Public Licence v. 2.0.
 ****************************************************************************/
#include <stdio.h>
#include "hexdump.h"

void hexdump(unsigned char *message, int length) {
    int i;
    for (i = 0; i < length; ++i) {
        if (i % 16 == 0) {
            if (i > 0) {
                printf("\n");
            }
            printf("%08x: ", i);
        }
        printf(" %02x", message[i]);
    }

    if (length > 0)
        printf("\n");
}

#ifdef UNIT_TEST
#include <stdlib.h>

void testLength(unsigned int length) {
    int i;
    unsigned char *msg = (unsigned char *) malloc(length);
    for (i = 0; i < length; ++i) msg[i] = i % 256;
    hexdump(msg, length);
}

int main(int argc, char **argv) {
    int i;
    for (i = 0; i < 35; ++i) {
        printf("test %d:\n", i);
        testLength(i);
    }
}
#endif

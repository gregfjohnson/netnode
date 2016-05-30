/****************************************************************************
 * hexhump.c
 * Copyright (c) 2016, Greg Johnson, Gnu Public Licence v. 2.0.
 ****************************************************************************/
#include <stdio.h>
#include "hexdump.h"

#define min(x,y) ((x) < (y) ? (x):(y))

static int printText(char *outBuf, int outLen, unsigned char *message, int length) {
    char *startOutBuf = outBuf;
    int len;
    int i;

    for (i = 0; i < 16 - length; ++i) {
        len = snprintf(outBuf, outLen, "   ");
        if (len > outLen - 1) len = outLen - 1;
        outBuf += len;
        outLen -= len;
    }

    len = snprintf(outBuf, outLen, "   |");
    if (len > outLen - 1) len = outLen - 1;
    outBuf += len;
    outLen -= len;

    for (i = 0; i < length; ++i) {
        unsigned char ch = message[i];

        if (ch >= 32 && ch <= 126) { len = snprintf(outBuf, outLen, "%c", ch); }
        else                       { len = snprintf(outBuf, outLen, "."); }
        if (len > outLen - 1) len = outLen - 1;
        outBuf += len;
        outLen -= len;
    }
    len = snprintf(outBuf, outLen, "|\n");
    if (len > outLen - 1) len = outLen - 1;
    outBuf += len;
    outLen -= len;

    return outBuf - startOutBuf;
}

int hexdump(char *outBuf, int outLen, unsigned char *message, int length) {
    char *startOutBuf = outBuf;
    int i;
    int len;
    for (i = 0; i < length; ++i) {
        if (i % 16 == 0) {
            if (i > 0) {
                len = printText(outBuf, outLen, &message[i - 16], 16);
                outBuf += len;
                outLen -= len;
            }
        }
        len = snprintf(outBuf, outLen, " %02x", message[i]);
        if (len > outLen - 1) len = outLen - 1;
        outBuf += len;
        outLen -= len;
    }

    if (length > 0) {
        int len = length % 16;
        if (len == 0) len = 16;
        len = printText(outBuf, outLen, &message[length - len], len);
        outBuf += len;
        outLen -= len;

    } else if (outLen > 0) {
        outBuf[0] = '\0';
    }

    return outBuf - startOutBuf;
}

#ifdef UNIT_TEST
#include <stdlib.h>
#include <string.h>

void testLength(unsigned int length) {
    int i;
    unsigned char *msg = (unsigned char *) malloc(length);
    char outMsg[1024];
    for (i = 0; i < length; ++i) msg[i] = i % 256;
    int len = hexdump(outMsg, 1024, msg, length);
    printf("%s", outMsg);
    printf("length %d, strlen %zu\n%s", len, strlen(outMsg), outMsg);
}

void testLengthPrintable(unsigned int length) {
    int i;
    unsigned char *msg = (unsigned char *) malloc(length);
    char outMsg[1024];
    for (i = 0; i < length; ++i) msg[i] = 32 + i % 127;
    int len = hexdump(outMsg, 1024, msg, length);
    printf("length %d, strlen %zu\n%s", len, strlen(outMsg), outMsg);
}

int main(int argc, char **argv) {
    int i;
    for (i = 0; i <= 35; ++i) {
        printf("test %d:\n", i);
        testLengthPrintable(i);
    }

    return 0;
}
#endif

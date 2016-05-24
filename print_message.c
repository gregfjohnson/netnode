#include <stdio.h>
#include <ctype.h>
#include "print_message.h"

static void print_chars(char *cbuf, int cbuf_len) {
    int j;
    for (j = cbuf_len; j < 16; j++) {
        printf("  ");
        if (j % 2 == 1) { printf(" "); }
    }
    printf("       |");
    
    for (j = 0; j < cbuf_len; j++) {
        if (isprint((unsigned int) cbuf[j])) {
            printf("%c", cbuf[j]);
        } else {
            printf(".");
        }
    }
    printf("|\r\n");
}

void print_message(char *buf, int msg_len) {
    int i;
    char cbuf[16];
    int this_byte = 0;
    char line_start;
    int len;

    printf("message length:  %d\r\n", msg_len);
    if (msg_len < 0) {
        printf("hmmm.  negative message length.\r\n");
    }
    if (msg_len <= 0) { return; }

    printf("%4d:  ", this_byte);

    len = (14 < msg_len) ? 14 : msg_len;

    for (i = 0; i < len; i++) {
        printf("%02x", 0xff & buf[i]);
        if (i % 2 == 1) { printf(" "); }
        cbuf[i] = (char) buf[i];
    }
    print_chars(cbuf, len);

    if (msg_len <= 14) { return; }

    msg_len -= 14;
    buf += 14;
    this_byte += 14;
    line_start = 1;

    for (i = 0; i < msg_len; i++) {
        if (line_start) {
            printf("%4d:  ", this_byte);
            line_start = 0;
            this_byte += 16;
        }
        printf("%02x", 0xff & buf[i]);
        if (i % 2 == 1) { printf(" "); }

        cbuf[i % 16] = (char) buf[i];
        if ((i + 1) % 16 == 0) {
            print_chars(cbuf, 16);
            line_start = 1;
        }
    }

    /* print block of "|...|" text for last (partial) line */
    if (msg_len % 16 != 0) {
        print_chars(cbuf, msg_len % 16);
    }

} /* print_message */

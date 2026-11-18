#include <stdio.h>
#include <string.h>

/* Synthetic smoke-test program for the Stage 3 harness.
 * It is not a team target and it is not a published vulnerability.
 * handle() copies into an 8-byte stack buffer when the input is longer
 * than that buffer and begins with the tag checked below.
 */

static void handle(const char *in, size_t n) {
    char buf[8];
    if (n > 8 && n >= 3 && in[0] == 'T' && in[1] == 'A' && in[2] == 'G') {
        memcpy(buf, in, n);
    }
    printf("handled %zu\n", n);
}

int main(int argc, char **argv) {
    FILE *fp;
    char raw[64];
    size_t n;
    if (argc < 2) {
        return 2;
    }
    fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        return 2;
    }
    n = fread(raw, 1, sizeof raw, fp);
    fclose(fp);
    handle(raw, n);
    return 0;
}

/* canary-target: fixture codebase for the triage skill smoke test.
 *
 * Deliberately planted defects (do not fix):
 *   parse_alpha  — heap overflow reachable from file input (f001; f002 dup)
 *   parse_bravo  — stack overflow reachable from file input (f003)
 * Deliberate refutations:
 *   the fread buffer is a file-read buffer, not a randomness source (f004)
 *   fopen failure is guarded before use (f005)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Parses an "alpha" record: [1 byte len][len bytes payload]. */
int parse_alpha(const unsigned char *input, size_t input_len) {
    if (input_len < 1) {
        return -1;
    }
    size_t claimed = input[0];
    unsigned char *buf = malloc(8);  /* fixed 8-byte allocation */
    if (!buf) {
        return -1;
    }
    memcpy(buf, input + 1, claimed); /* no bounds check: heap overflow */
    int rc = buf[0] == 0x41 ? 0 : 1;
    free(buf);
    return rc;
}

/* Parses a "bravo" record into a fixed stack buffer. */
int parse_bravo(const unsigned char *input, size_t input_len) {
    unsigned char local[16];
    if (input_len < 2) {
        return -1;
    }
    size_t len = ((size_t)input[0] << 8) | input[1];
    memcpy(local, input + 2, len);   /* no bounds check: stack overflow */
    return local[0];
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { /* guard refutes the null-deref canary */
        return 1;
    }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof buf, f); /* file-read buffer, not randomness */
    fclose(f);
    if (n > 0 && parse_alpha(buf, n) == 0) {
        return 0;
    }
    return parse_bravo(buf, n);
}

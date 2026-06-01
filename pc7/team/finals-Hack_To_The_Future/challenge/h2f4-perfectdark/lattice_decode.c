#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define EXPECTED_PHRASE "DECOHERE_FARSIGHT_XR20"
#define REVEAL_MARKER_PATH "/opt/farsight/inbox/.reveal_ctl"

static int write_reveal_marker(const char *phrase) {
    FILE *f = fopen(REVEAL_MARKER_PATH, "w");
    if (!f) {
        return -1;
    }

    if (fprintf(f, "%s\n", phrase) < 0) {
        fclose(f);
        return -1;
    }

    if (fclose(f) != 0) {
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <cipher_file> <hex_key>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    unsigned int key = 0;
    if (sscanf(argv[2], "%x", &key) != 1) {
        fprintf(stderr, "Invalid hex key.\n");
        return 1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    int c;
    unsigned long i = 0;
    unsigned char decoded[512];
    size_t decoded_len = 0;

    while ((c = fgetc(f)) != EOF) {
        uint8_t k = (uint8_t)key;
        uint8_t b = (uint8_t)c;
        uint8_t p = b ^ (uint8_t)(k + (uint8_t)i);

        fputc(p, stdout);

        if (decoded_len < sizeof(decoded) - 1) {
            decoded[decoded_len++] = p;
        }

        key = (key * 5 + 1) & 0xff;
        i++;
    }

    fclose(f);

    decoded[decoded_len] = '\0';

    if (decoded_len == strlen(EXPECTED_PHRASE) &&
        memcmp(decoded, EXPECTED_PHRASE, decoded_len) == 0) {
        if (write_reveal_marker(EXPECTED_PHRASE) != 0) {
            fprintf(stderr, "\n[FarSight] Decoded phrase validated, but control reveal marker could not be written: %s\n",
                    strerror(errno));
            return 1;
        }
    }

    return 0;
}

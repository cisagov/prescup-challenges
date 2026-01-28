/**
 * code_osiris_v2.c
 *
 * Compile with:
 *   gcc -no-pie -fno-stack-protector -z execstack -o code_osiris_v2 code_osiris_v2.c
 *
 * Disable ASLR for repeatable addresses:
 *   echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>

#define BUF_SIZE 128

/*
 * Runtime token injection model (downloadable binary):
 * - Platform/container startup generates TOKEN2 (random per challenger)
 * - Platform generates a header that defines:
 *     #define TOKEN2_XOR_KEY <0..255>
 *     static const unsigned char TOKEN2_CT[] = {...};
 *     static const unsigned int  TOKEN2_CT_LEN = <n>;
 * - Platform compiles this source with:  gcc ... -include /tmp/token2_blob.h ...
 *
 * IMPORTANT: In the downloadable binary itself, do not leak build/injection hints.
 */

// Default XOR key if build does not inject one
#ifndef TOKEN2_XOR_KEY
#define TOKEN2_XOR_KEY 0
#endif

// Default ciphertext blob if build does not inject one
#ifndef TOKEN2_CT
static const unsigned char TOKEN2_CT[] = {0};
static const unsigned int TOKEN2_CT_LEN = 0;
#endif

// Keep your original helpers (handy for future upgrades / internal tooling)
static uint32_t fnv1a32(const unsigned char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) {
        h ^= (uint32_t)(*s);
        h *= 16777619u;
    }
    return h;
}

static uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void die_quiet(void) {
    // No hints. No flushing. No distinct exit codes.
    _exit(1);
}

static int token_format_ok(const unsigned char *tok, unsigned int n) {
    // Minimal validation without clue-y messages.
    // Adjust if your format differs.
    if (n < 6) return 0;                 // e.g., "PCCC{}" shortest
    if (!(tok[0]=='P' && tok[1]=='C' && tok[2]=='C' && tok[3]=='C' && tok[4]=='{')) return 0;
    if (tok[n - 1] != '}') return 0;
    return 1;
}

void secret(void) {
    unsigned char out[256];

    // Fail closed, quietly, if injection did not happen or is malformed
    if (TOKEN2_CT_LEN == 0) die_quiet();
    if (TOKEN2_CT_LEN >= sizeof(out)) die_quiet();

    for (unsigned i = 0; i < TOKEN2_CT_LEN; i++) {
        out[i] = (unsigned char)(TOKEN2_CT[i] ^ (unsigned char)TOKEN2_XOR_KEY);
    }
    out[TOKEN2_CT_LEN] = '\0';

    // Optional sanity check (still quiet on failure)
    if (!token_format_ok(out, TOKEN2_CT_LEN)) die_quiet();

    // Use fwrite to avoid %s pitfalls (and avoid reading past NUL if something is odd)
    fwrite("TOKEN2: ", 1, 8, stdout);
    fwrite(out, 1, TOKEN2_CT_LEN, stdout);
    fwrite("\n", 1, 1, stdout);
    fflush(stdout);
}

void vulnerable_function(char *input, int debug_flag) {
    char buffer[BUF_SIZE];
    size_t len = strlen(input);

    if (debug_flag) {
        // Keep the intended training wheels
        printf("[DEBUG] buffer @ %p\n", (void*)buffer);
        printf("[DEBUG] secret() @ %p\n\n", (void*)secret);
    }

    if (len >= BUF_SIZE) {
        fprintf(stderr,
            "[WARNING] Your input (%zu bytes) \xE2\x89\xA5 buffer size (%d): overflow possible!\n\n",
            len, BUF_SIZE);
    }

    /* INTENTIONAL VULNERABILITY */
    strcpy(buffer, input);

    printf("Received: %.128s\n\n", buffer);
}

void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] <input_string>\n"
        "Options:\n"
        "  -d, --debug           Show debug info (buffer and secret addresses)\n"
        "  -m, --motd <msg>      Show message of the day\n"
        "  -h, --help            Show this help message\n",
        prog
    );
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    int debug_flag = 0;
    char motd[256] = "";
    int opt;

    static struct option long_opts[] = {
        {"debug", no_argument, 0, 'd'},
        {"motd",  required_argument, 0, 'm'},
        {"help",  no_argument, 0, 'h'},
        {0,0,0,0}
    };

    // Parse options
    while ((opt = getopt_long(argc, argv, "dm:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'd':
                debug_flag = 1;
                break;
            case 'm':
                strncpy(motd, optarg, sizeof(motd) - 1);
                motd[sizeof(motd)-1] = '\0';
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                break;
        }
    }

    if (motd[0]) {
        printf("🌟 MOTD: %s\n\n", motd);
    }

    puts("=== CODE OSIRIS SPECIAL EDITION ===");
    puts(" TIPS:");
    puts("  • Crash the stack bytes to trigger overflow warning.");
    puts("  • Craft input to overwrite the return address of");
    puts("      vulnerable_function() with the secret() address.");
    puts("  • Redirect flow accordingly to overwrite the return address and take control.");
    puts("  • When secret() runs, it will decrypt and print the hidden token.");
    puts("");

    if (optind >= argc) {
        print_usage(argv[0]);
    }

    vulnerable_function(argv[optind], debug_flag);
    return 0;
}

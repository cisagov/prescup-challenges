#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void decode_bytes(const unsigned char *in, size_t len, unsigned char key, char *out, size_t out_sz) {
    size_t n = len;
    if (out_sz == 0) return;
    if (n >= out_sz) n = out_sz - 1;
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)(in[i] ^ key);
    }
    out[n] = '\0';
}

static void get_phrase(char *out, size_t out_sz) {
    static const unsigned char enc[] = {
        0x11, 0x10, 0x16, 0x1a, 0x1d, 0x10, 0x07, 0x10,
        0x0a, 0x13, 0x14, 0x07, 0x06, 0x1c, 0x12, 0x1d,
        0x01, 0x0a, 0x0d, 0x07, 0x67, 0x65
    };
    decode_bytes(enc, sizeof(enc), 0x55, out, out_sz);
}

static void get_phrase_path(char *out, size_t out_sz) {
    static const unsigned char enc[] = {
        0x7a, 0x3a, 0x25, 0x21, 0x7a, 0x33, 0x34, 0x27, 0x26, 0x3c, 0x32, 0x3d,
        0x21, 0x7a, 0x3c, 0x3b, 0x37, 0x3a, 0x2d, 0x7a, 0x26, 0x3d, 0x20, 0x21,
        0x31, 0x3a, 0x22, 0x3b, 0x0a, 0x25, 0x3d, 0x27, 0x34, 0x26, 0x30, 0x7b,
        0x21, 0x2d, 0x21
    };
    decode_bytes(enc, sizeof(enc), 0x55, out, out_sz);
}

static void get_token_path(char *out, size_t out_sz) {
    static const unsigned char enc[] = {
        0x7a, 0x27, 0x20, 0x3b, 0x7a, 0x7b, 0x33, 0x26,
        0x31, 0x7b, 0x39, 0x3a, 0x36, 0x3e
    };
    decode_bytes(enc, sizeof(enc), 0x55, out, out_sz);
}

static void get_target1(char *out, size_t out_sz) {
    static const unsigned char enc[] = {
        0x7a, 0x20, 0x26, 0x27, 0x7a, 0x39, 0x3a, 0x36, 0x34, 0x39, 0x7a, 0x39,
        0x3c, 0x37, 0x7a, 0x7b, 0x33, 0x26, 0x0a, 0x37, 0x3a, 0x3a, 0x21, 0x7a,
        0x33, 0x34, 0x27, 0x26, 0x3c, 0x32, 0x3d, 0x21, 0x31, 0x7b, 0x25, 0x2c
    };
    decode_bytes(enc, sizeof(enc), 0x55, out, out_sz);
}

static void get_target2(char *out, size_t out_sz) {
    static const unsigned char enc[] = {
        0x7a, 0x20, 0x26, 0x27, 0x7a, 0x39, 0x3a, 0x36, 0x34, 0x39, 0x7a, 0x39,
        0x3c, 0x37, 0x7a, 0x7b, 0x33, 0x26, 0x0a, 0x37, 0x3a, 0x3a, 0x21, 0x7a,
        0x31, 0x34, 0x2c, 0x37, 0x27, 0x30, 0x34, 0x3e, 0x0a, 0x27, 0x30, 0x39,
        0x34, 0x2c, 0x7b, 0x25, 0x2c
    };
    decode_bytes(enc, sizeof(enc), 0x55, out, out_sz);
}

static int is_numeric(const char *s) {
    if (!s || !*s) return 0;
    for (; *s; ++s) {
        if (!isdigit((unsigned char)*s)) return 0;
    }
    return 1;
}

static int cmdline_contains(pid_t pid, const char *needle) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) return 0;
    buf[n] = '\0';

    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }

    return strstr(buf, needle) != NULL;
}

static int process_exists(const char *needle) {
    DIR *d = opendir("/proc");
    if (!d) return 0;

    struct dirent *de;
    int found = 0;

    while ((de = readdir(d)) != NULL) {
        if (!is_numeric(de->d_name)) continue;

        pid_t pid = (pid_t)atoi(de->d_name);
        if (pid <= 1) continue;

        if (cmdline_contains(pid, needle)) {
            found = 1;
            break;
        }
    }

    closedir(d);
    return found;
}

static int phrase_valid(void) {
    char phrase_path[256];
    char expected[64];
    get_phrase_path(phrase_path, sizeof(phrase_path));
    get_phrase(expected, sizeof(expected));

    FILE *f = fopen(phrase_path, "r");
    if (!f) return 0;

    char buf[128] = {0};
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }

    char extra[2];
    if (fgets(extra, sizeof(extra), f) != NULL) {
        fclose(f);
        return 0;
    }

    fclose(f);

    buf[strcspn(buf, "\r\n")] = '\0';
    return strcmp(buf, expected) == 0;
}

int main(void) {
    char target1[256], target2[256], token_path[256];
    get_target1(target1, sizeof(target1));
    get_target2(target2, sizeof(target2));
    get_token_path(token_path, sizeof(token_path));

    if (!phrase_valid()) {
        fprintf(stderr, "[Stage: FarSight Destruction] Shutdown phrase invalid or missing.\n");
        return 1;
    }

    if (process_exists(target1) || process_exists(target2)) {
        fprintf(stderr, "[Stage: FarSight Destruction] FarSight runtime still active.\n");
        return 1;
    }

    FILE *tf = fopen(token_path, "r");
    if (!tf) {
        perror("[Stage: FarSight Destruction] fopen");
        return 1;
    }

    char token[256] = {0};
    if (!fgets(token, sizeof(token), tf)) {
        fclose(tf);
        fprintf(stderr, "[Stage: FarSight Destruction] Failed to read token.\n");
        return 1;
    }
    fclose(tf);

    token[strcspn(token, "\r\n")] = '\0';

    printf("[Stage: FarSight Destruction] Temporal anchor decohered.\n");
    printf("✅ TOKEN4: %s\n", token);
    return 0;
}

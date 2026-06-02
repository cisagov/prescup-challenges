#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
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

static void get_destroy_src(char *out, size_t out_sz) {
    static const unsigned char enc[] = {
        0x7a, 0x20, 0x26, 0x27, 0x7a, 0x39, 0x3a, 0x36, 0x34, 0x39, 0x7a, 0x39,
        0x3c, 0x37, 0x7a, 0x7b, 0x33, 0x26, 0x0a, 0x37, 0x3a, 0x3a, 0x21, 0x7a,
        0x33, 0x34, 0x27, 0x26, 0x3c, 0x32, 0x3d, 0x21, 0x0a, 0x31, 0x30, 0x26,
        0x21, 0x27, 0x3a, 0x2c, 0x7b, 0x37, 0x3c, 0x3b
    };
    decode_bytes(enc, sizeof(enc), 0x55, out, out_sz);
}

static void get_destroy_dst(char *out, size_t out_sz) {
    static const unsigned char enc[] = {
        0x7a, 0x3a, 0x25, 0x21, 0x7a, 0x33, 0x34, 0x27, 0x26, 0x3c, 0x32, 0x3d,
        0x21, 0x7a, 0x33, 0x34, 0x27, 0x26, 0x3c, 0x32, 0x3d, 0x21, 0x0a, 0x31,
        0x30, 0x26, 0x21, 0x27, 0x3a, 0x2c
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

static void print_help(const char *prog) {
    printf("FarSight Control Interface\n");
    printf("Usage: %s --execute\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  --execute    Execute FarSight shutdown sequence\n");
    printf("  -h, --help   Show this help menu\n");
}

static int read_phrase(char *out, size_t out_sz) {
    char phrase_path[256];
    char expected[64];
    get_phrase_path(phrase_path, sizeof(phrase_path));
    get_phrase(expected, sizeof(expected));

    FILE *f = fopen(phrase_path, "r");
    if (!f) {
        fprintf(stderr, "[FarSight Control] Shutdown phrase file missing.\n");
        return 0;
    }

    if (!fgets(out, (int)out_sz, f)) {
        fclose(f);
        fprintf(stderr, "[FarSight Control] Shutdown phrase file is empty.\n");
        return 0;
    }

    char extra[2];
    if (fgets(extra, sizeof(extra), f) != NULL) {
        fclose(f);
        fprintf(stderr, "[FarSight Control] Shutdown phrase file contains extra content.\n");
        return 0;
    }

    fclose(f);

    out[strcspn(out, "\r\n")] = '\0';

    if (strcmp(out, expected) != 0) {
        fprintf(stderr, "[FarSight Control] Invalid shutdown phrase.\n");
        return 0;
    }

    return 1;
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

static int terminate_target(const char *needle) {
    DIR *d = opendir("/proc");
    if (!d) return 0;

    struct dirent *de;
    pid_t pids[256];
    size_t count = 0;

    while ((de = readdir(d)) != NULL) {
        if (!is_numeric(de->d_name)) continue;

        pid_t pid = (pid_t)atoi(de->d_name);
        if (pid <= 1) continue;

        if (cmdline_contains(pid, needle)) {
            if (count < sizeof(pids) / sizeof(pids[0])) {
                pids[count++] = pid;
            }
        }
    }
    closedir(d);

    for (size_t i = 0; i < count; i++) {
        kill(pids[i], SIGTERM);
    }

    usleep(300000);

    for (size_t i = 0; i < count; i++) {
        if (kill(pids[i], 0) == 0) {
            kill(pids[i], SIGKILL);
        }
    }

    return (int)count;
}

static int copy_file(const char *src, const char *dst, mode_t mode) {
    if (access(dst, F_OK) == 0) {
        return 0;
    }

    int in = open(src, O_RDONLY | O_NOFOLLOW);
    if (in < 0) return -1;

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", dst);

    int out = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0700);
    if (out < 0) {
        close(in);
        return -1;
    }

    char buf[4096];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w < 0) {
                close(in);
                close(out);
                unlink(tmp);
                return -1;
            }
            off += w;
        }
    }

    if (n < 0) {
        close(in);
        close(out);
        unlink(tmp);
        return -1;
    }

    if (fchown(out, 0, 0) != 0) {
        close(in);
        close(out);
        unlink(tmp);
        return -1;
    }

    if (fchmod(out, mode) != 0) {
        close(in);
        close(out);
        unlink(tmp);
        return -1;
    }

    close(in);
    if (close(out) != 0) {
        unlink(tmp);
        return -1;
    }

    if (rename(tmp, dst) != 0) {
        unlink(tmp);
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 &&
        (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_help(argv[0]);
        return 0;
    }

    if (argc != 2 || strcmp(argv[1], "--execute") != 0) {
        fprintf(stderr, "[FarSight Control] Invalid invocation.\n");
        return 1;
    }

    char phrase[128] = {0};
    if (!read_phrase(phrase, sizeof(phrase))) {
        return 1;
    }

    if (setgid(0) != 0 || setuid(0) != 0) {
        fprintf(stderr, "[FarSight Control] Failed to acquire elevated privileges.\n");
        return 1;
    }

    char target1[256], target2[256], destroy_src[256], destroy_dst[256];
    get_target1(target1, sizeof(target1));
    get_target2(target2, sizeof(target2));
    get_destroy_src(destroy_src, sizeof(destroy_src));
    get_destroy_dst(destroy_dst, sizeof(destroy_dst));

    terminate_target(target1);
    terminate_target(target2);

    if (copy_file(destroy_src, destroy_dst, 04555) != 0) {
        fprintf(stderr, "[FarSight Control] Failed to materialize destruction interface: %s\n", strerror(errno));
        return 1;
    }

    puts("[FarSight Control] Temporal relay collapse authorized.");
    puts("[FarSight Control] Lattice and relay daemons terminated.");
    puts("[FarSight Control] Destruction interface materialized.");

    return 0;
}

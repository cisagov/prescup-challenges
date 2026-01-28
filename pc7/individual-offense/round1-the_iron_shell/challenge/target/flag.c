#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>    // for PATH_MAX

#define XOR_KEY 0xAB

static void decrypt_and_print(unsigned char *encrypted, size_t len) {
    char *decrypted = malloc(len + 1);
    if (!decrypted) {
        perror("malloc");
        return;
    }
    for (size_t i = 0; i < len; i++) {
        decrypted[i] = encrypted[i] ^ XOR_KEY;
    }
    decrypted[len] = '\0';
    printf("%s\n", decrypted);
    free(decrypted);
}

static int is_numeric(const char *s) {
    if (!*s) return 0;
    for (; *s; ++s) if (!isdigit(*s)) return 0;
    return 1;
}

int main(void) {
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir(/proc)");
        return 1;
    }

    struct dirent *entry;
    while ((entry = readdir(proc))) {
        if (entry->d_type != DT_DIR || !is_numeric(entry->d_name))
            continue;

        char comm_path[PATH_MAX];
        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);

        FILE *f = fopen(comm_path, "r");
        if (!f) continue;

        char comm[256];
        if (fgets(comm, sizeof(comm), f)) {
            comm[strcspn(comm, "\n")] = 0;
            if (strcmp(comm, "sshd") == 0) {
                pid_t pid = (pid_t)atoi(entry->d_name);
                if (kill(pid, SIGKILL) < 0)
                    fprintf(stderr, "kill(%d): %s\n", pid, strerror(errno));
            }
        }
        fclose(f);
    }

    closedir(proc);
    
    // Placeholder - will be replaced by entrypoint.sh with XOR-encrypted token
    unsigned char encrypted_flag[] = {0xef, 0xc6, 0xc7, 0xc4, 0xc0};
    size_t flag_len = sizeof(encrypted_flag);
    
    decrypt_and_print(encrypted_flag, flag_len);
    return 0;
}
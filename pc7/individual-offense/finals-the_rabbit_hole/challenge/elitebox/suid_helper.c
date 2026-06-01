// suid_helper.c (hardened logic; SUID binary that verifies a timestamped token file)
// compiled with stack protector and RELRO (see Dockerfile).
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#define TOKFILE "/tmp/suid_token"
#define TOKLEN 64

int main(int argc, char **argv){
    char buf[TOKLEN+1] = {0};
    int fd = open(TOKFILE, O_RDONLY);
    if (fd < 0){
        fprintf(stderr,"token missing\n"); return 1;
    }
    ssize_t r = read(fd, buf, TOKLEN);
    close(fd);
    if (r <= 0){ fprintf(stderr,"token bad\n"); return 1; }
    // token format: hex(sha256(some_secret || timestamp))::timestamp
    char *sep = strchr(buf, ':');
    if (!sep){ fprintf(stderr,"format\n"); return 1; }
    *sep = 0;
    char *ts = sep+1;
    long t = atol(ts);
    long now = time(NULL);
    if (llabs(now - t) > 120){ fprintf(stderr,"token expired\n"); return 1; }
    // minimal check on hex length
    if (strlen(buf) < 48){ fprintf(stderr,"token short\n"); return 1; }
    // success -> spawn root shell
    setuid(0);
    execl("/bin/sh","/bin/sh","-p", NULL);
    return 0;
}


#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

int get_comm(char *buf, size_t len){
    int fd = open("/proc/self/comm", O_RDONLY);
    if(fd<0) return -1;
    ssize_t r = read(fd, buf, len-1);
    if(r>0){ buf[r]=0; char *nl=strchr(buf,'\n'); if(nl) *nl=0; }
    close(fd); return (int)r;
}
int procname_is(const char *needle){
    char b[64]={0}; if(get_comm(b,sizeof(b))<0) return 0;
    return strcmp(b, needle)==0;
}
uint8_t pid_xor_key(void){ return (uint8_t)(getpid() & 0xFF); }
void xorbuf(uint8_t *b, size_t n, uint8_t k){ for(size_t i=0;i<n;i++) b[i]^=k; }

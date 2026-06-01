
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

static int under_ptrace(){
    errno=0; if(ptrace(PTRACE_TRACEME,0,0,0)==-1){ return 1; } return 0;
}

int benign_op(){ puts("optic-helper: benign mode"); return 0; }

int netlock(){
    const char *t2=getenv("TOKEN2"); if(!t2) t2="OR{t2}";
    size_t n=strlen(t2)+1;
    void *p=mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memcpy(p, t2, n);
    pause();
    return 0;
}

int main(){ if(under_ptrace()) return netlock(); return benign_op(); }

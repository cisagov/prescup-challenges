
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static uint8_t pid_xor_key(void){ return (uint8_t)(getpid() & 0xFF); }

static void write_real_shimmer(void){
    const char *t1=getenv("TOKEN1"); if(!t1) t1="PCCC{Contact_Support_01}";
    uint8_t key = pid_xor_key();
    int fd=open("/dev/shm/optic.real",O_CREAT|O_WRONLY|O_TRUNC,0600); if(fd<0) return;
    size_t n=strlen(t1);
    for(size_t i=0;i<n;i++){
        uint8_t b = ((uint8_t)t1[i]) ^ key;
        write(fd,&b,1);
    }
    close(fd);
}

static void stage_boot_arg(void){
    // ROT13-encode TOKEN4 into a clue file
    const char *t4=getenv("TOKEN4"); if(!t4) t4="PCCC{Contact_Support_04}";
    FILE *f=fopen("/opt/clues/boot.enc","w"); if(!f) return;
    for(const char *s=t4; *s; ++s){
        int c=*s;
        if(c>='a' && c<='z') c = 'a' + ((c - 'a' + 13) % 26);
        else if(c>='A' && c<='Z') c = 'A' + ((c - 'A' + 13) % 26);
        fputc(c, f);
    }
    fclose(f);
}

int main(){
    umask(0077);
    mkdir("/dev/shm", 0755);
    mkdir("/opt/clues", 0755);
    write_real_shimmer();
    stage_boot_arg();
    // Passive daemon; network beacons are handled by entrypoint loop
    for(;;){ sleep(60); }
    return 0;
}

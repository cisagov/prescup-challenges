
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

int main(){
    int s=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(s<0){perror("socket"); return 1;}
    unsigned char buf[2048];
    while(1){
        ssize_t n=recv(s,buf,sizeof(buf),0); if(n<=0) continue;
        for(ssize_t i=0;i<n-12;i++) if(!memcmp(buf+i, ".optic.local", 12)){
            ssize_t start=i-1; if(start<0) start=0;
            for(ssize_t k=i-1;k>=0;k--){ if(buf[k]==0){ start=k+1; break; } }
            fwrite(buf+start,1,(size_t)(i-start), stdout); fputc('\n', stdout);
            fflush(stdout);
        }
    }
}

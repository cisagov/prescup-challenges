
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <string.h>

int main(){
    FILE *out=fopen("residual.mem","wb"); if(!out){perror("residual.mem"); return 1;}
    DIR *d=opendir("/var/optic/res"); if(!d){perror("/var/optic/res"); return 1;}
    struct dirent *de; int idx=0; uint8_t b[4096];
    while((de=readdir(d))){
        if(strncmp(de->d_name,"frag_",5)) continue;
        char path[256]; snprintf(path,sizeof(path),"/var/optic/res/%s",de->d_name);
        FILE *f=fopen(path,"rb"); if(!f) continue;
        size_t n=fread(b,1,sizeof(b),f); fclose(f);
        for(size_t i=0;i<n;i++) b[i]^=((idx*13)&0xff);
        fwrite(b,1,n,out); idx++;
    }
    closedir(d); fclose(out);
    fprintf(stderr, "Wrote residual.mem\n");
    return 0;
}

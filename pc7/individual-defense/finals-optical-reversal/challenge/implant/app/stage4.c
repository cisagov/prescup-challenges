
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Simulates a flag guarded by one byte at known offset, similar to Arcadian writeup.
uint8_t STAGE4_LOCK = 1;

int main(int argc, char **argv){
    (void)argc;(void)argv;
    if(STAGE4_LOCK==0){
        const char *t = getenv("TOKEN4"); if(!t) t = "PCCC{Contact_Support_04}";
        printf("Bypass detected! TOKEN4: %s\n", t);
    }else{
        puts("Service OK. No issues detected.");
    }
    return 0;
}

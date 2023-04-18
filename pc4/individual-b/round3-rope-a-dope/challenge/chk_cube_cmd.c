// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

/*

compile:
`gcc -m32 -fno-stack-protector -no-pie -o chk_cube_cmd chk_cube_cmd.c -Wall`

setuid-root:
`chown root:root chk_cube_cmd; chmod u+s chk_cube_cmd`

disable aslr:
`echo 0 > /proc/sys/kernel/randomize_va_space`

*/

#include <stdio.h>
#include <string.h>

void respond(char *input) {
        char buf[64];
        strcpy(buf, input);
        printf("cube_cmd: %s\n", buf);
}

int main(int argc, char *argv[]) {
        if (argc != 2) {
                printf("\nUsage: %s <cube_cmd>\n", argv[0]);
                return 1;
        }
        respond(argv[1]);
        printf("Verified.\n");
        return 0;
}

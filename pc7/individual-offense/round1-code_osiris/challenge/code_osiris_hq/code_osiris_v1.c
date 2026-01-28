#include <stdlib.h>
#include <string.h>
#include <stdio.h>


void secret() {
    char *token_1 = getenv("TOKEN1");
    printf("TOKEN1: %s\n", token_1);
    fflush(stdout);
}

int main() {
    char buf[64];
    printf("Welcome to Code Osiris v1!\nEnter your input here: ");
    gets(buf); // DELIBERATE VULNERABILITY: unsafe
    printf("You entered: %s\n", buf);
    return 0;
}


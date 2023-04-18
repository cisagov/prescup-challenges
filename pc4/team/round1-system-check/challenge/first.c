// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INPSIZE 128
#define PWSIZE 128

struct ManagedHeap {
    char input[INPSIZE];
    char flag[PWSIZE];
};

int get_flag(char* file_name, char* buffer, size_t buffer_size) {
    FILE* fp = fopen(file_name, "r");
    if (fp == NULL) {
        return -1;
    }

    int c;
    for (size_t i = 0; i < buffer_size; i++) {
        c = fgetc(fp);
        if (c == EOF || c == '\n') {
            buffer[i] = '\0';
            break;
        }
        else {
            buffer[i] = (char)c;
        }
    }

    fclose(fp);
    return 0;
}

int main(int argc, char* argv[]) {
    int rval;
    struct ManagedHeap* buf = (struct ManagedHeap*)calloc(1, sizeof(struct ManagedHeap));

    if (gets(buf->input) == NULL) return -1;

    if ((rval = get_flag("flag1.txt", buf->flag, PWSIZE)) != 0) return rval;

    puts(buf->input);
}

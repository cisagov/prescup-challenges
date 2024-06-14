// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#include <stdio.h>
#include <string.h>

char mapping[] = "qwertyuiopasdfghjklzxcvbnm";
char ref[] = "#####";
int ref_len = 5;

void here_is_the_secret() {
  char secret[100];
  FILE *fi = fopen("secret.txt", "r");
  fgets(secret, sizeof secret, fi);
  fclose(fi);
  puts(secret);
  FILE *fo = fopen("done.txt", "w");
  fputs("Successfully get the secret.", fo);
  fclose(fo);
}

int crack_me(char *buffer) {
  printf("Tell me the secret (all in lower case) by command line: .\\crypto.exe some_string\n");
  printf("Your input: ");
  puts(buffer);
  if (strlen(buffer) != ref_len) {
    return 0;
  }
  int correct = 0;
  for (int i = 0; i < ref_len; ++i) {
    char c = buffer[i];
    if ('a' <= c && c <= 'z') {
      correct += (mapping[c - 'a'] == ref[i]);
    }
  }
  printf("%d/%d correct chars in the input string\n", correct, ref_len);
  return correct == ref_len;
}

int main(int argc, char **argv) {
  if (crack_me(argv[1]) == 1) {
    printf("Here is the secret: ");
    here_is_the_secret();
  } else {
    printf("This is not the answer :(\n");
  }
}

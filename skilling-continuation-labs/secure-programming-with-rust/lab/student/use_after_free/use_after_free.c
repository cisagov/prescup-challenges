
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
  int* int_arr = malloc(sizeof(int) * 1000);

  for (int i = 0; i < 1000; i++) {
    *(int_arr + i) = i;
  }

  //printf("Value located at the fifth index of the array is: %d\n", *(int_arr+5));

  free(int_arr);

  printf("Value of fifth index after running 'free' function is: %d\n", *(int_arr+5));
}




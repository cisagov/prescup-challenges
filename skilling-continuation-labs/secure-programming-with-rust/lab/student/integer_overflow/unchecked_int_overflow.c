
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#include <stdint.h>
#include <stdio.h>

int main(int argc, char** argv) {
  int max_int = INT32_MAX;

  printf("%d\n", max_int);

  max_int += 1;

  printf("%d\n", max_int);
}




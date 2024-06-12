// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// Used to have RTLD_NEXT defined in dlfcn.h
#define _GNU_SOURCE

// dlsym and RTLD_NEXT
#include <dlfcn.h>
// Include the real version of AES_ige_encrypt so we can call it later
#include <openssl/aes.h>
// puts, printf, and snprintf
#include <stdio.h>
// calloc and free
#include <stdlib.h>

// We need to define a function pointer type with the same signature as the
// function we want to hold a pointer to.
typedef void (*AES_ige_encrypt_t)(const unsigned char *in, unsigned char *out,
                                  size_t length, const AES_KEY *key,
                                  unsigned char *ivec, const int enc);
// Then we create a static variable to hold the function pointer.
static AES_ige_encrypt_t real_AES_ige_encrypt = NULL;

// We can use this function to print the passed buffer to stdout and then use
// `grep` to filter for the `token` tag.
void print_sized(const unsigned char *buf, size_t length) {
  unsigned char *buf_print = calloc(length + 1, sizeof(unsigned char));
  if (buf_print == NULL) {
    puts("Could not calloc a buffer in print_sized()");
    return;
  }

  snprintf(buf_print, (length + 1) * sizeof(unsigned char), "%s", buf);
  printf("Plaintext: |%s|\n", buf_print);

  free(buf_print);
}

// In order to intercept a function, we need to make our own version of it
// that calls the original function.
void AES_ige_encrypt(const unsigned char *in, unsigned char *out, size_t length,
                     const AES_KEY *key, unsigned char *ivec, const int enc) {
  if (!real_AES_ige_encrypt) {
    // Passing RTLD_NEXT to dlsym searches for the next occurance of the given
    // symbol. We could call dlerror() to check for errors after, but we'll skip
    // it here.
    real_AES_ige_encrypt = dlsym(RTLD_NEXT, "AES_ige_encrypt");
  }

  real_AES_ige_encrypt(in, out, length, key, ivec, enc);
  // We could print on both encrypt and decrypt, but the challenge program only
  // decrypts.
  if (enc == AES_DECRYPT) {
    print_sized(out, length);
  }
}

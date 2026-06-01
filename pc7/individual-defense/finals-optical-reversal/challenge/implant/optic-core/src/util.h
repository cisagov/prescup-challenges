
#pragma once
#include <stddef.h>
#include <stdint.h>
int get_comm(char *buf, size_t len);
int procname_is(const char *needle);
uint8_t pid_xor_key(void);
void xorbuf(uint8_t *b, size_t n, uint8_t k);

\
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
  libboot.so — ELD ingestion support library

  This library contains an intentionally unsafe packet normalizer that was
  originally written for "trusted" roadside uplinks. It is shipped as a binary
  firmware snapshot for analysis.

  The vulnerability is a bounded overflow: input length is clamped to 264 bytes,
  allowing controlled overwrite of two 32-bit fields after a 256-byte buffer.
*/

static uint32_t fnv1a32(const unsigned char *s, int n) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < n; i++) {
        h ^= (uint32_t)s[i];
        h *= 16777619u;
    }
    return h;
}

typedef struct __attribute__((packed)) Frame {
    unsigned char tmp[256];
    uint32_t fuse;
    uint32_t guard;
} Frame;

void process_chunk(const unsigned char* buf, int len) {
    Frame f;

    // Default state
    f.fuse  = 0xA17E11D0u;
    f.guard = 0xC0FFEE00u;

    // Bounded overflow (still unsafe): allows overwriting fuse+guard without trashing the stack frame.
    if (len > 264) len = 264;
    memcpy(f.tmp, buf, (size_t)len);

    // Guard is derived from payload content (first 64 bytes).
    // The constant is meant to prevent "random" corruption from triggering a release.
    uint32_t want_guard = fnv1a32(f.tmp, 64) ^ 0xA5C3F1D7u;

    if (f.fuse == 0x0BADC0DEu && f.guard == want_guard) {
        puts("AUTH_UNSEALED");
        fflush(stdout);
    } else {
        // Keep output stable for fuzzing / analysis; do not leak state directly.
        puts("INGEST_OK");
        fflush(stdout);
    }
}

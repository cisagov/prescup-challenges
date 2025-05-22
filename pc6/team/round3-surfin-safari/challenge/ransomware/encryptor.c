#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/types.h>
#include <errno.h>

#define ROTL32(v, n) ((v << n) | (v >> (32 - n)))

#define QUARTERROUND(a, b, c, d) \
  a += b; d ^= a; d = ROTL32(d, 16); \
  c += d; b ^= c; b = ROTL32(b, 12); \
  a += b; d ^= a; d = ROTL32(d, 8);  \
  c += d; b ^= c; b = ROTL32(b, 7);

typedef struct {
  uint32_t state[16];  // ChaCha20 state matrix (4x4)
} ChaCha20Ctx;

// ChaCha20 block function (Generates 64 bytes of keystream)
void chacha20_block(ChaCha20Ctx *ctx, uint32_t output[16]) {
  int i;
  memcpy(output, ctx->state, sizeof(ctx->state));

  // Perform 20 rounds (10 iterations of column and diagonal rounds)
  for (i = 0; i < 10; i++) {
    // Column rounds
    QUARTERROUND(output[0], output[4], output[8], output[12]);
    QUARTERROUND(output[1], output[5], output[9], output[13]);
    QUARTERROUND(output[2], output[6], output[10], output[14]);
    QUARTERROUND(output[3], output[7], output[11], output[15]);
    // Diagonal rounds
    QUARTERROUND(output[0], output[5], output[10], output[15]);
    QUARTERROUND(output[1], output[6], output[11], output[12]);
    QUARTERROUND(output[2], output[7], output[8], output[13]);
    QUARTERROUND(output[3], output[4], output[9], output[14]);
  }

  // Add the original state
  for (i = 0; i < 16; i++) {
    output[i] += ctx->state[i];
  }
}

// Initialize the ChaCha20 state
void chacha20_init(ChaCha20Ctx *ctx, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
  static const char *constants = "expand 32-byte k";

  // Set up the initial state
  ctx->state[0] = ((uint32_t *)constants)[0];
  ctx->state[1] = ((uint32_t *)constants)[1];
  ctx->state[2] = ((uint32_t *)constants)[2];
  ctx->state[3] = ((uint32_t *)constants)[3];

  // Load the key
  memcpy(&ctx->state[4], key, 32);

  // Counter
  ctx->state[12] = counter;

  // Nonce
  memcpy(&ctx->state[13], nonce, 12);
}

// Encrypt or decrypt data (ChaCha20 is symmetric)
void chacha20_crypt(ChaCha20Ctx *ctx, uint8_t *data, size_t len) {
  uint32_t keystream[16];
  uint8_t keystream_bytes[64];
  size_t i;

  for (i = 0; i < len; i++) {
    if (i % 64 == 0) {  // Generate new keystream block every 64 bytes
      chacha20_block(ctx, keystream);
      memcpy(keystream_bytes, keystream, 64);
      ctx->state[12]++;  // Increment counter to get a new block
    }
    data[i] ^= keystream_bytes[i % 64];  // XOR plaintext with keystream
  }
}

void encrypt_file(const char *filepath, const uint8_t key[32], const uint8_t nonce[12]) {
  uint32_t counter = 1; // Counter (usually starts at 1)
  FILE *file = fopen(filepath, "rb");

  if (!file) {
    perror("Failed to open file");
    return;
  }

  // Check if the filepath is a directory
  struct stat path_stat;
  stat(filepath, &path_stat);
  if (S_ISDIR(path_stat.st_mode)) {
    fprintf(stderr, "Error: %s is a directory\n", filepath);
    fclose(file);
    return;
  }

  // Get file size
  fseek(file, 0, SEEK_END);
  size_t filesize = ftell(file);
  fseek(file, 0, SEEK_SET);

  printf("File size: %zu bytes\n", filesize);

  // Read file content
  uint8_t *buffer = (uint8_t *)malloc(filesize);
  if (!buffer) {
    perror("Failed to allocate memory");
    fclose(file);
    return;
  }
  fread(buffer, 1, filesize, file);
  fclose(file);

  // Initialize ChaCha20 context
  ChaCha20Ctx ctx;
  chacha20_init(&ctx, key, nonce, counter);

  // Encrypt file content
  chacha20_crypt(&ctx, buffer, filesize);

  // Save encrypted content to new file
  char enc_filepath[256];
  snprintf(enc_filepath, sizeof(enc_filepath), "./out/%s.enc", strrchr(filepath, '/') ? strrchr(filepath, '/') + 1 : filepath);
  printf("Encrypted file saved to: %s\n", enc_filepath);
  FILE *enc_file = fopen(enc_filepath, "wb");
  if (!enc_file) {
    perror("Failed to open encrypted file");
    free(buffer);
    return;
  }
  fwrite(buffer, 1, filesize, enc_file);
  fclose(enc_file);

  free(buffer);
}

// Function to convert hex string to byte array
void hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_len) {
  for (size_t i = 0; i < bytes_len; i++) {
    sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
  }
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <key in hex> <nonce in hex>\n", argv[0]);
    return 1;
  }

  uint8_t key[32];
  uint8_t nonce[12];

  if (strlen(argv[1]) != 64 || strlen(argv[2]) != 24) {
    fprintf(stderr, "Error: Key must be 64 hex characters and nonce must be 24 hex characters\n");
    return 1;
  }

  hex_to_bytes(argv[1], key, sizeof(key));
  hex_to_bytes(argv[2], nonce, sizeof(nonce));

  DIR *dir;
  struct dirent *entry;

  if ((dir = opendir("./in")) != NULL) {
    while ((entry = readdir(dir)) != NULL) {
      if (entry->d_type == DT_REG) {  // Check if it's a regular file
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "./in/%s", entry->d_name);
        printf("Encrypting file: %s\n", filepath);
        encrypt_file(filepath, key, nonce);
      }
    }
    closedir(dir);
  } else {
    perror("Failed to open directory");
  }

  return 0;
}

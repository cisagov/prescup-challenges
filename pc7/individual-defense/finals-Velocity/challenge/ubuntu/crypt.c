#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <ctype.h>
#include <stddef.h>

#define MAX_HOSTNAME 128
#define MAX_KEYSTR   64

// ---------------------------------------------------------------------
// Magic trailer: used to mark encrypted files without changing names
// ---------------------------------------------------------------------
static const unsigned char MAGIC_TRAILER[4] = { 0xDE, 0xAD, 0xC0, 0xDE };

static bool file_has_magic_trailer(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        return false;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return false;
    }

    long size = ftell(fp);
    if (size < 4) {
        fclose(fp);
        return false;
    }

    if (fseek(fp, size - 4, SEEK_SET) != 0) {
        fclose(fp);
        return false;
    }

    unsigned char buf[4];
    if (fread(buf, 1, 4, fp) != 4) {
        fclose(fp);
        return false;
    }
    fclose(fp);

    return buf[0] == MAGIC_TRAILER[0] &&
           buf[1] == MAGIC_TRAILER[1] &&
           buf[2] == MAGIC_TRAILER[2] &&
           buf[3] == MAGIC_TRAILER[3];
}

// ---------------------------------------------------------------------
// Token logic: constant token split across two encoded arrays
// Plaintext token: "PCCC{encrypt_binary_token}"
// XOR key for token decoding: 0x92
// ---------------------------------------------------------------------

static const unsigned char tk = 0x92;

// "PCCC" XOR 0x92
static const unsigned char enc1[] = {
    0xC2, 0xD1, 0xD1, 0xD1
};
static const size_t enc_1_len = sizeof(enc1);

// "{token_6_crypt}" XOR 0x92
// static const unsigned char enc2[] = {
//     0xE9, 0xE6, 0xFD, 0xF9, 0xF7, 0xFC, 0xCD, 0xA4,
//     0xCD, 0xF1, 0xE0, 0xEB, 0xE2, 0xE6, 0xEF
// };

static const unsigned char enc2[] = {
    PLACEHOLDER
};

static const size_t enc2_LEN = sizeof(enc2);

static void decode_token(char *out, size_t out_sz) {
    const size_t total = enc_1_len + enc2_LEN;

    if (out_sz < total + 1) {
        exit(1);
    }

    size_t pos = 0;

    for (size_t i = 0; i < enc_1_len; i++) {
        out[pos++] = (char)(enc1[i] ^ tk);
    }
    for (size_t i = 0; i < enc2_LEN; i++) {
        out[pos++] = (char)(enc2[i] ^ tk);
    }

    out[pos] = '\0';
}

//////////////////// HOSTNAME + MAC-HEX KEY LOGIC ////////////////////

// Convert ASCII string to hex string ("abc" → "616263")
static void ascii_to_hex(const char *in, char *out, size_t out_sz) {
    size_t pos = 0;
    for (size_t i = 0; in[i] != '\0' && pos + 2 < out_sz; i++) {
        pos += snprintf(out + pos, out_sz - pos, "%02x",
                        (unsigned char)in[i]);
    }
    out[pos] = '\0';
}

// Read MAC from eth0 or eth1, fallback to default hex if both fail
// Returns 0 on success (including fallback), -1 only if out_sz too small.
static int get_mac_hex(char *out, size_t out_sz) {
    const char *paths[] = {
        "/sys/class/net/eth0/address",
        "/sys/class/net/eth1/address",
        NULL
    };

    char buf[64];
    size_t pos;
    int i;

    // Try each interface path in order
    for (i = 0; paths[i] != NULL; i++) {
        FILE *fp = fopen(paths[i], "r");
        if (!fp) {
            continue;  // try next path
        }

        if (!fgets(buf, sizeof(buf), fp)) {
            fclose(fp);
            continue;
        }
        fclose(fp);

        // Strip colons, keep only hex digits
        pos = 0;
        for (size_t j = 0; buf[j] != '\0' && pos + 1 < out_sz; j++) {
            if (isxdigit((unsigned char)buf[j])) {
                out[pos++] = (char)tolower((unsigned char)buf[j]);
            }
        }

        out[pos] = '\0';

        if (pos > 0) {
            // Successfully parsed a MAC
            return 0;
        }
        // otherwise, try next interface
    }

    // eth0/eth1 failed → use deterministic default
    static const char *fallback_mac_hex = "001122334455";

    size_t fallback_len = strlen(fallback_mac_hex);
    if (fallback_len + 1 > out_sz) {
        // Buffer too small even for fallback
        return -1;
    }

    snprintf(out, out_sz, "%s", fallback_mac_hex);
    return 0;
}

// XOR two hex strings; pad shorter one with 00 bytes
static void xor_hex_strings(const char *hex_a, const char *hex_b,
                            char *out, size_t out_sz)
{
    size_t len_a = strlen(hex_a) / 2; // number of bytes
    size_t len_b = strlen(hex_b) / 2;
    size_t max_len = (len_a > len_b) ? len_a : len_b;

    size_t pos = 0;

    for (size_t i = 0; i < max_len && pos + 2 < out_sz; i++) {
        unsigned int a = 0, b = 0;

        // Read a byte from hostname hex
        if (i < len_a)
            sscanf(hex_a + i*2, "%2x", &a);

        // Read a byte from MAC hex
        if (i < len_b)
            sscanf(hex_b + i*2, "%2x", &b);

        unsigned int x = (a ^ b) & 0xFF;

        // Append two hex digits to output
        pos += snprintf(out + pos, out_sz - pos, "%02x", x);
    }

    out[pos] = '\0';
}

// Derive the encryption key as hex string from hostname and MAC
static int derive_encryption_key(const char *hostname,
                               char *out,
                               size_t out_sz)
{
    char hostname_hex[256] = {0};
    char mac_hex[64]       = {0};
    char xor_key[256]      = {0};

    // hostname → hex
    ascii_to_hex(hostname, hostname_hex, sizeof(hostname_hex));

    // MAC → hex (eth0 → eth1 → default)
    if (get_mac_hex(mac_hex, sizeof(mac_hex)) != 0) {
        return -1;
    }

    // XOR hostname_hex with mac_hex (as hex bytes) → xor_key
    xor_hex_strings(hostname_hex, mac_hex, xor_key, sizeof(xor_key));

    if (xor_key[0] == '\0') {
        return -1;
    }

    // Copy to caller buffer (trimmed to out_sz)
    snprintf(out, out_sz, "%s", xor_key);
    return 0;
}

/////////////////////////// END KEY LOGIC ////////////////////////////

// ---------------------------------------------------------------------
// Original helper prototypes
// ---------------------------------------------------------------------
void xor_crypt_file(const char *filename, const char *key, int encrypting);
void process_directory_files(char choice, const char *key, const char *self_name);
const char *get_base_filename(const char *full_path);

/**
 * @brief Extracts the base filename from a full path string.
 */
const char *get_base_filename(const char *full_path) {
    const char *last_slash = strrchr(full_path, '/');
    if (last_slash == NULL) {
        return full_path;
    } else {
        return last_slash + 1;
    }
}

/**
 * @brief Encrypts or decrypts a single file using a simple XOR cipher.
 *        Uses MAGIC_TRAILER to mark encrypted files, without changing filenames.
 */
void xor_crypt_file(const char *filename, const char *key, int encrypting) {
    FILE *fp_in = NULL, *fp_out = NULL;
    int c;
    size_t key_len = strlen(key);
    size_t key_index = 0;
    char temp_filename[FILENAME_MAX];

    // Build temp filename: "<filename>.tmp"
    snprintf(temp_filename, sizeof(temp_filename), "%s.tmp", filename);

    fp_in = fopen(filename, "rb");
    if (fp_in == NULL) {
        return;
    }

    fp_out = fopen(temp_filename, "wb");
    if (fp_out == NULL) {
        fclose(fp_in);
        return;
    }

    if (!encrypting) {
        // Decrypting: do not XOR the last 4 magic bytes.
        if (fseek(fp_in, 0, SEEK_END) != 0) {
            fclose(fp_in);
            fclose(fp_out);
            remove(temp_filename);
            return;
        }

        long size = ftell(fp_in);
        if (size < 4) {
            fclose(fp_in);
            fclose(fp_out);
            remove(temp_filename);
            return;
        }

        long data_size = size - 4; // bytes we actually XOR/decrypt

        if (fseek(fp_in, 0, SEEK_SET) != 0) {
            fclose(fp_in);
            fclose(fp_out);
            remove(temp_filename);
            return;
        }

        long processed = 0;
        while (processed < data_size && (c = fgetc(fp_in)) != EOF) {
            fputc(c ^ key[key_index], fp_out);
            key_index = (key_index + 1) % key_len;
            processed++;
        }

        // We ignore the last 4 bytes (magic trailer).

    } else {
        // Encrypting: XOR all bytes, then append magic trailer.
        while ((c = fgetc(fp_in)) != EOF) {
            fputc(c ^ key[key_index], fp_out);
            key_index = (key_index + 1) % key_len;
        }

        // Append magic trailer at the end of encrypted data.
        for (int i = 0; i < 4; i++) {
            fputc(MAGIC_TRAILER[i], fp_out);
        }
    }

    fclose(fp_in);
    fclose(fp_out);

    // Atomically replace original with temp
    if (rename(temp_filename, filename) != 0) {
        remove(temp_filename);
        return;
    }
}

/**
 * @brief Processes all files in the current working directory.
 *        Encrypt: XOR + add magic trailer (if not already present).
 *        Decrypt: only files that already have the magic trailer.
 */
void process_directory_files(char choice, const char *key, const char *self_name) {
    DIR *d;
    struct dirent *dir;
    char *dot = ".";
    char *dotdot = "..";

    d = opendir(".");
    if (d == NULL) {
        return;
    }

    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, dot) == 0 || strcmp(dir->d_name, dotdot) == 0) {
            continue;
        }

        if (strcmp(dir->d_name, self_name) == 0) {
            continue;
        }

        if (strcmp(dir->d_name, "lastlog") == 0 ||
        strcmp(dir->d_name, "wtmp") == 0 ||
        strcmp(dir->d_name, "btmp") == 0 ||
        strcmp(dir->d_name, "faillog") == 0) {
            continue;
    }

        if (dir->d_type == DT_REG) {
            const char *fname = dir->d_name;

            if (choice == 'e') {
                // Encrypt: skip if already has magic trailer
                if (!file_has_magic_trailer(fname)) {
                    xor_crypt_file(fname, key, 1);
                }
            } else if (choice == 'd') {
                // Decrypt: only touch files with magic trailer
                if (file_has_magic_trailer(fname)) {
                    xor_crypt_file(fname, key, 0);
                }
            }
        }
    }
    closedir(d);
}

int main(int argc, char *argv[]) {
    char choice;

    if (argc < 2 || argv == NULL) {
        fprintf(stderr, "usage: ./crypt [OPTIONS]\nOPTIONS: e (encrypt), d (decrypt)\n");
        return 1;
    }

    const char *self_name = get_base_filename(argv[0]);
    choice = argv[1][0];
    if (choice != 'e' && choice != 'd') {
        fprintf(stderr, "usage: ./crypt [OPTIONS]\nOPTIONS: e (encrypt), d (decrypt)\n");
        return 1;
    }

    // ---- Change to the directory where this binary lives ---------------
    {
        char exe_path[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len != -1) {
            exe_path[len] = '\0';

            char *last_slash = strrchr(exe_path, '/');
            if (last_slash) {
                *last_slash = '\0';  // exe_path now just the directory
                self_name = last_slash + 1;
                if (chdir(exe_path) != 0) {
                    perror("err");
                } else {
                    // After chdir, self_name is just the basename
                    self_name = last_slash + 1;
                }
            }
        } 
    }

    // ---- Derive key from hostname + MAC (hex XOR) ---------------------
    char hostname[MAX_HOSTNAME] = {0};
    if (gethostname(hostname, sizeof(hostname)) != 0 || hostname[0] == '\0') {
        return 1;
    }

    char encryption_key[MAX_KEYSTR] = {0};
    if (derive_encryption_key(hostname, encryption_key, sizeof(encryption_key)) != 0) {
        return 1;
    }

    if (choice == 'e') {
        // Encrypt: use derived key string directly (no user input)
        process_directory_files(choice, encryption_key, self_name);

    } else if (choice == 'd') {
        // Decrypt: require player to enter the correct derived key
        char input_key[256];

        printf("enter decryption key: ");
        if (fgets(input_key, sizeof(input_key), stdin) == NULL) {
            return 1;
        }
        input_key[strcspn(input_key, "\n")] = 0;

        if (strcmp(input_key, encryption_key) != 0) {
            puts("Wrong key.");
            return 1;
        }

        // Key is correct → reveal token, then decrypt files
        char token[64];
        decode_token(token, sizeof(token));
        puts("Correct key. Token:");
        puts(token);
        memset(token, 0, sizeof(token));

        process_directory_files(choice, encryption_key, self_name);
    } else {
        fprintf(stderr, "Invalid choice. Please enter 'e' or 'd'.\n");
        return 1;
    }

    return 0;
}

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

// WARNING: Hardcoding the key directly in the source code is insecure.
// This is for demonstration purposes only.
const char *E_KEY = "PLACEHOLDER";

// Global constant for the encrypted file extension
const char *ENCRYPTED_EXT = ".xor";

// Function Prototypes
void xor_crypt_file(const char *filename, const char *key, int encrypting);
void process_directory_files(char choice, const char *key, const char *self_name);
const char *get_base_filename(const char *full_path);

/**
 * @brief Extracts the base filename from a full path string.
 * @param full_path The original path string (e.g., "./file_tool" or "/usr/bin/file_tool").
 * @return A pointer to the character immediately following the last forward slash.
 */
const char *get_base_filename(const char *full_path) {
    // strrchr finds the last occurrence of a character in a string
    const char *last_slash = strrchr(full_path, '/');

    // If no slash is found (e.g., the name is just "file_tool"), return the original string
    if (last_slash == NULL) {
        return full_path;
    } else {
        // Otherwise, return the pointer to the character *after* the last slash
        return last_slash + 1;
    }
}

/**
 * @brief Encrypts or decrypts a single file using a simple XOR cipher.
 * @param filename The path to the input file.
 * @param key The encryption/decryption key.
 * @param encrypting Flag: 1 for encryption, 0 for decryption.
 */
void xor_crypt_file(const char *filename, const char *key, int encrypting) {
    FILE *fp_in, *fp_out;
    int c;
    size_t key_len = strlen(key);
    size_t key_index = 0;
    char output_filename[FILENAME_MAX];

    // Open input file for reading
    fp_in = fopen(filename, "rb");
    if (fp_in == NULL) {
        perror("Error opening input file");
        return;
    }

    // Determine the output filename
    if (!encrypting) {
        // For decryption, remove the ".xor" suffix
        char temp_name[FILENAME_MAX];
        strncpy(temp_name, filename, sizeof(temp_name) - 1);
        temp_name[sizeof(temp_name) - 1] = '\0'; // Ensure null-termination
        char *ext_pos = strstr(temp_name, ENCRYPTED_EXT);
        if (ext_pos != NULL) {
            *ext_pos = '\0'; // Truncate the string to remove the extension
        }
        snprintf(output_filename, FILENAME_MAX, "%s", temp_name);
    } else {
        // For encryption, add the ".xor" suffix
        snprintf(output_filename, FILENAME_MAX, "%s%s", filename, ENCRYPTED_EXT);
    }

    // Open output file for writing
    fp_out = fopen(output_filename, "wb");
    if (fp_out == NULL) {
        perror("Error opening output file");
        fclose(fp_in);
        return;
    }

    // Read input file byte by byte and perform XOR operation
    while ((c = fgetc(fp_in)) != EOF) {
        fputc(c ^ key[key_index], fp_out);
        key_index = (key_index + 1) % key_len;
    }

    // Close files
    fclose(fp_in);
    fclose(fp_out);

    printf("Processed file '%s'. Output saved to '%s'.\n", filename, output_filename);

    // Remove the original file
    if (remove(filename) == 0) {
        printf("Original file '%s' removed successfully.\n", filename);
    } else {
        perror("Error removing original file");
    }
}

/**
 * @brief Processes all files in the current working directory.
 * @param choice 'e' for encrypt, 'd' for decrypt.
 * @param key The key to use for the XOR operation.
 * @param self_name The name of the executable to ignore.
 */
void process_directory_files(char choice, const char *key, const char *self_name) {
    DIR *d;
    struct dirent *dir;
    char *dot = ".";
    char *dotdot = "..";
    char *file_ext;

    // Open the current directory
    d = opendir(".");
    if (d == NULL) {
        perror("Error opening current directory");
        return;
    }

    // Read directory entries
    while ((dir = readdir(d)) != NULL) {
        // Skip "." and ".." to avoid infinite recursion
        if (strcmp(dir->d_name, dot) == 0 || strcmp(dir->d_name, dotdot) == 0) {
            continue;
        }

        // Skip the executable itself
        if (strcmp(dir->d_name, self_name) == 0) {
            printf("Skipping self: %s\n", self_name);
            continue;
        }

        // Check if the entry is a regular file
        if (dir->d_type == DT_REG) {
            if (choice == 'e') {
                // If encrypting, process files that are NOT already encrypted
                file_ext = strstr(dir->d_name, ENCRYPTED_EXT);
                if (file_ext == NULL || strcmp(file_ext, ENCRYPTED_EXT) != 0) {
                    xor_crypt_file(dir->d_name, key, 1);
                }
            } else if (choice == 'd') {
                // If decrypting, process files that ARE encrypted
                file_ext = strstr(dir->d_name, ENCRYPTED_EXT);
                if (file_ext != NULL && strcmp(file_ext, ENCRYPTED_EXT) == 0) {
                    xor_crypt_file(dir->d_name, key, 0);
                }
            }
        }
    }
    closedir(d);
}

int main(int argc, char *argv[]) {
    char choice;

    // Check if the executable name is available
    if (argc < 2 || argv == NULL) {
        fprintf(stderr, "usage: ./xcryptzor [OPTIONS]\nOPTIONS: e (encrypt), d (decrypt)\n");
        return 1;
    }
    // Correctly determine the base name of the executable
    const char *self_name = get_base_filename(argv[0]);

    choice = argv[1][0];  
    if (choice != 'e' && choice != 'd') {
        fprintf(stderr, "usage: ./xcryptzor [OPTIONS]\nOPTIONS: e (encrypt), d (decrypt)\n");
        return 1;
    }
    /*
    printf("Enter 'e' for encrypt or 'd' for decrypt all files in this directory: ");
    if (scanf(" %c", &choice) != 1) {
        fprintf(stderr, "Invalid input.\n");
        return 1;
    }
    */
    // Clear the input buffer to consume the leftover newline character
    //clear_input_buffer();

    if (choice == 'e') {
        process_directory_files(choice, E_KEY, self_name);
    } else if (choice == 'd') {
        char key[256];
        printf("enter decryption key: ");
        
        // Now fgets will wait for the new input
        if (fgets(key, sizeof(key), stdin) == NULL) {
            fprintf(stderr, "Error reading key input.\n");
            return 1;
        }

        // Remove the trailing newline character from the key
        key[strcspn(key, "\n")] = 0;

        process_directory_files(choice, key, self_name);
    } else {
        fprintf(stderr, "Invalid choice. Please enter 'e' or 'd'.\n");
        return 1;
    }

    return 0;
}

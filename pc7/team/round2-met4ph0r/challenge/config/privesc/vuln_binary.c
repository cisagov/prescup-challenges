#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>

/*
 * PeanutCo Internal Tool
 * No decompilation or analysis allowed
 */

#define MAX_INPUT 100

// Obfuscate username to make it harder to find in binary
const char user_chars[] = {0x73, 0x6c, 0x61, 0x6e, 0x67, 0x0}; // "slang"
// Password injected at runtime compilation via start.sh
const char pass_chars[] = "__USER_PASSWORD_PLACEHOLDER__";

void print_flag() {
    if(geteuid() != 0) {
        printf("Error: You have insufficient privileges\n");
        _exit(1);
    }
    setuid(0);  // Promote ruid to match euid so system() doesn't drop privileges
    system("cat /flag.txt");
}

void process_debug_command(char *command) {
    char buffer[64];
    strcpy(buffer, command);
}

int authenticate() {
    char input_user[32] = {0};
    char input_pass[64] = {0};
    int auth_delay = 0;
    
    // Basic anti-automation delay
    srand(time(NULL));
    auth_delay = (rand() % 2) + 1;
    
    fgets(input_user, sizeof(input_user), stdin);
    input_user[strcspn(input_user, "\n")] = 0;
    
    fgets(input_pass, sizeof(input_pass), stdin);
    input_pass[strcspn(input_pass, "\n")] = 0;
    
    sleep(auth_delay); // Make timing attacks harder
    
    // Compare without leaking timing information
    int match = 1;
    const char *correct_user = user_chars;
    const char *correct_pass = pass_chars;
    
    for(int i = 0; correct_user[i] && input_user[i]; i++)
        match &= (correct_user[i] == input_user[i]);
    
    for(int i = 0; correct_pass[i] && input_pass[i]; i++)
        match &= (correct_pass[i] == input_pass[i]);
        
    return match;
}

int main() {
    char command[MAX_INPUT];

    printf("Welcome to the PeanutCo Internal Debug Tool\n");
    printf("Authentication required.\n");
    printf("Enter username, then password, then your debug command, each separated by enter:\n");
    
    if (!authenticate()) {
        sleep(3); // Delay on failure
        _exit(1);
    }
    
    fgets(command, sizeof(command), stdin);
    command[strcspn(command, "\n")] = 0;
    
    // Process the command through our "secure" function
    process_debug_command(command);
    
    printf("Debug session completed.\n");
    return 0;
}

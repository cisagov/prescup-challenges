
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// SECTION 1 CODE BLOCK


int authenticate(char *username, char *password) {
    char pass[MAX_PASSWORD] = {0};
    char user[MAX_USERNAME] = {0};
    
    int isAuthenticated = 0; 

    // SECTION 2 CODE BLOCK 
    
    
    if (strcmp(user, "admin") == 0 && strcmp(pass, "password") == 0) {
        isAuthenticated = 1; 
    }

    return isAuthenticated;
}

int main() {
    char username[20] = {0};
    char password[20] = {0};
    
    printf("Enter username: ");

    // SECTION 3 CODE BLOCK

    
    
    printf("Enter password: ");

    // SECTION 4 CODE BLOCK

    

    int auth_result = authenticate(username,password);

    if (auth_result) {
        printf("Login successful!\n");
    } else {
        printf("Login failed!\n");
    }

    return 0;
}


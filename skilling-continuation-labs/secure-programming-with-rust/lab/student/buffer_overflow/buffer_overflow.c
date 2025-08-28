
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#include <stdio.h>
#include <string.h>

int main() {
    char password[10]; 
    char correct_password[] = "password";   
    int is_authenticated = 0;

    printf("Enter Admin password: ");
    scanf("%s", password);
    

    if (strcmp(correct_password,password) == 0) {
        is_authenticated = 1;
    }

    if (is_authenticated) {
        printf("Access granted!\n");
    } else {
        printf("Access denied.\n");
    }
    
    return 0;
}



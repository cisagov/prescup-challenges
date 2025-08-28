
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// Code to insert

// SECTION 1 
// Creates two immutable variables with the name MAX_USERNAME and MAX_PASSWORD that are assigned the value 10
#define MAX_USERNAME 10
#define MAX_PASSWORD 10

// SECTION 2 
// Copy the values from the char variables username and password to the char variables user and pass, respectfully.
strcpy(user, username);
strcpy(pass, password);

// SECTION 3 
// Create char variable bufferUsername with allocated size of 20, and then retrieve input from user to assign to that variable. Check if the string entered is longer than the accepted size and exit if it is.
char bufferUsername[20];
scanf("%s", bufferInput);
if (strlen(bufferInput) > sizeof(username)) {
    printf("Username cannot be over 20 characters.");
    return 0;
}

// SECTION 4
// Create char variable bufferPassword with allocated size of 20, and then retrieve input from user to assign to that variable. Check if the string entered is longer than the accepted size and exit if it is.
char bufferPassword[20];
scanf("%s", bufferPassword);
if (strlen(bufferPassword) > sizeof(password)) {
    printf("Password cannot be over 20 characters.");
    return 0;
}

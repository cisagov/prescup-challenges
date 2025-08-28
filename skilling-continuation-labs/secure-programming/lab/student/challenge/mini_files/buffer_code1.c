
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

//Code to insert

// SECTION 1 
// Creates two immutable variables with the name MAX_USERNAME and MAX_PASSWORD that are assigned the value 10
#define MAX_USERNAME 10 
#define MAX_PASSWORD 10

// SECTION 2 
// Copy the values from the char variables username and password to the char variables user and pass, respectfully.
strcpy(user, username);
strcpy(pass, password);

// SECTION 3 
// Retrieve input from the user to assign to the char variable username and then remove newline character from the string.
fgets(username, sizeof(username), stdin);
username[strcspn(username, "\n")] = 0; 

// SECTION 4 
// Retrieve input from the user to assign to the char variable password and then remove newline character from the string.
fgets(password, sizeof(password), stdin);
password[strcspn(password, "\n")] = 0; 

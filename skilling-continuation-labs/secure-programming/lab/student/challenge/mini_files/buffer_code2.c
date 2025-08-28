
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// Code to insert

// SECTION 1 
// Creates two immutable variables with the name MAX_USERNAME and MAX_PASSWORD that are assigned the value 20
#define MAX_USERNAME 20
#define MAX_PASSWORD 20

// SECTION 2 
// Copy the values from the char variables username and password to the char variables user and pass, respectfully.
strncpy(pass, password, sizeof(pass)-1);
strncpy(user, username, sizeof(user)-1);

// SECTION 3 
// Retrieve input from the user to assign to the char variable username without a newline character present.
scanf("%s",username);

// SECTION 4 
// Retrieve input from the user to assign to the char variable password without a newline character present.
scanf("%s",password);


// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// Code to insert

// SECTION 1 CODE BLOCK 
// Create the variable balance as an double data type with the value 0. Create the variable deposit as an unsigned long integer data type.
double balance = 0;
unsigned long int deposit;

// SECTION 2 CODE BLOCK 
// Create char variable depositString with allocated size of 256, and then retrieve input from user to assign to that variable. 
// Check if the string entered contains a negative number or is larger than the max size the variable deposit can hold, it either of these checks are true, re-prompt user for valid number.
// Otherwise, Assign the integer value of the string entered to the variable deposit.
char depositString[256];
fgets(depositString, 256, stdin);
if (strstr(depositString, "-") != NULL || strlen(depositString) > 10) {
    printf("Invalid deposit amount entered. Please try again.\n");
    continue;
}
deposit =  atoi(depositString);


// SECTION 3 CODE BLOCK 
// Check if the value of the variable deposit will make the value of the variable balance pass the max valid value for the double data-type. If it does, print string and exit.
// Otherwise, Add the values of the variables deposit and balance together and assign the sum to the variable balance and then print the new value to the terminal.
if (balance > DBL_MAX - deposit){
    printf("Account unable to deposit money. Exiting...");
    return 0;
}
balance += deposit;
printf("\nSuccessfully deposited %u.\nNew balance: %lf\n", deposit, balance);


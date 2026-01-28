
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// Code to insert

// SECTION 1 CODE BLOCK 
// Create the variable balance as an unsigned long long integer data type with the value 0.0. Create the variable deposit as an unsigned long long integer data type.
unsigned long long int balance = 0.0;
unsigned long long int deposit;

// SECTION 2 CODE BLOCK 
// Retrieve input from the user to assign to the variable deposit as an unsigned long long integer. 
// Check the value of the number entered and if it surpasses the max size of the unsigned long long integer data type, print string to the terminal and assign max valid number to deposit variable.
scanf("%llu",&deposit);
if (deposit >= ULLONG_MAX){
    printf("Max value of deposit is llu",ULLONG_MAX);
    deposit = ULLONG_MAX;
}

// SECTION 3 CODE BLOCK 
// Add the values of the variables deposit and balance together and assign the sum to the variable balance and then print the new value to the terminal.
balance += deposit;
printf("\nSuccessfully deposited %llu.\nNew balance: %llu\n", deposit, balance);



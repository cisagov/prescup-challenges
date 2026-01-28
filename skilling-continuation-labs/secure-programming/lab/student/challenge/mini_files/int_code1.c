
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// Code to insert

// SECTION 1 CODE BLOCK
// Create the variable balance as an unsigned integer data type with the value 0. Create the variable deposit as an integer data type.
unsigned int balance = 0;
int deposit;

// SECTION 2 CODE BLOCK 
// Retrieve input from the user to assign to the variable deposit as an integer.
scanf("%d", &deposit);

// SECTION 3 CODE BLOCK 
// Add the values of the variables deposit and balance together and assign the sum to the variable balance and then print the new value to the terminal.
balance += deposit;
printf("\nSuccessfully deposited %d.\nNew balance: %u\n", deposit, balance);



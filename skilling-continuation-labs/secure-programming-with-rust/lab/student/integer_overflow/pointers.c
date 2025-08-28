
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#include <stdio.h>

int main() {
    int example_array[3] = {5, 10, 15};
    int *example_pointer = &example_array[0];

    printf("The value of the first entry in the array 'example_array' is: %d\n", example_array[0]); // Basic use of variable and printing its value
    printf("The memory address of the first entry in the array 'example_array' is: %p\n", &example_array[0]); // Utilizes the `&` character to print the memory address of the array entry.
    printf("The value of the first entry in the array 'example_array' using the variable 'example_pointer': %d\n", *example_pointer); // Utilizes the `*` character to print the value pointed to in a pointer variable.
    printf("The memory address of the first entry in the array 'example_array' using the variable 'example_pointer': %p\n\n", example_pointer); // Prints the memory address assigned to the example_pointer variable.

    return 0;
}


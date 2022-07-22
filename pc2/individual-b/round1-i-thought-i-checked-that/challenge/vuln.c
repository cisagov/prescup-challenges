/*
 * Copyright 2022 Carnegie Mellon University.
 * Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
 * root or contact permission@sei.cmu.edu for full terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

char *start = "Token is: ";
char *one = "d41bec09";
char *two = "4841ac7d";
char *three = "b0ce748a";
char *four = "a28a1efd";



int func_1(){
	char *five = malloc(strlen(three) + strlen(four) + strlen(two) + strlen(one) + 1);
	strcpy(five, three);
	strcat(five, two);
	strcat(five, four);
	strcat(five, one);
	
	puts(five);
	
	return 0;
}

void func_2(){
	char buff[18];
	printf("%s", "Enter a string >");
	return gets(buff);
}
	

int main(){

	FILE *file;
	file = fopen("./input", "r");
	short num = 0;
	
	if (file == NULL){
		printf("%s", "File does not exist. Must create an input file.\n");
		exit(1);
	}
	else{
		printf("%s", "File opened.\n");
		fscanf(file, "%hd", &num);
		printf("Num is %hd\n", num);

		if(num > 3 || num < 0){
			printf("%s", "The number in the file must be less than 3 and bigger than 0\n");
			exit(1);
		}
		else{
			printf("%s", "Number meets requirements.\n");
			rewind(file);
			sleep(num);
			num = 0;
			fscanf(file, "%hd", &num);
			printf("Num is %hd now\n", num);
			if(num != 9925) {
				printf("%s", "Number must be 9925\n");
			}
			else{
				func_2();
			}				
				
		}
	}

	fclose(file);
	return 0;
}

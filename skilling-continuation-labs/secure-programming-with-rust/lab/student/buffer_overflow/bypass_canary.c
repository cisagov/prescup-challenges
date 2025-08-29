
// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

#include <stdio.h>
#include <string.h>

void vulnerable_function() {
    char var1[10] = "";
    char var2[10] = "";
    char var3[10] = "";
    char var4[10] = "";
    char var5[10] = "";
    char var6[10] = "";
    char var7[10] = "";
    char var8[10] = "";
    char var9[10] = "";
    char var10[10] = "";

    printf("Before overflow:\n");
    printf("var1: %s\n", var1);
    printf("var2: %s\n", var2);
    printf("var3: %s\n", var3);
    printf("var4: %s\n", var4);
    printf("var5: %s\n", var5);
    printf("var6: %s\n", var6);
    printf("var7: %s\n", var7);
    printf("var8: %s\n", var8);
    printf("var9: %s\n", var9);
    printf("var10: %s\n", var10);

    printf("Enter a value for variable 'var1': ");
    scanf("%s", var1);

    printf("After overflow:\n");
    printf("var1: %s\n", var1);
    printf("var2: %s\n", var2);
    printf("var3: %s\n", var3);
    printf("var4: %s\n", var4);
    printf("var5: %s\n", var5);
    printf("var6: %s\n", var6);
    printf("var7: %s\n", var7);
    printf("var8: %s\n", var8);
    printf("var9: %s\n", var9);
    printf("var10: %s\n", var10);
}

int main() {
    vulnerable_function();
    return 0;
}



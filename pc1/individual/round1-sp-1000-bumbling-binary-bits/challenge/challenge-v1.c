/*
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
*/

// What is the output of the following program given the inputs 17, 43

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define qq 32
#define zz 8
#define yy 24
#define xx 16
#define ww 31
#define tt 2


int f1(int x) {
    return (1 << x) + 1;
}

int f2(int x) {
     int result = (1 << x);
     result += 4;
     return result;
}

int f3(int x, int y) {
  return (~(x&y)) & (~( (~x)&(~y) ));
}

int f4(int x) {
  int a =  170;
  int b = (a << zz) + a;
  int c = (b << xx) + b;
  int d = x & c;
  int e = d ^ c;
  return !e;
}

int f5(int x) {
  return ~x + 1;
}

int f6(int x, int y, int z) {
  int a = (!x + ~0x00);
  return ((~a) & z) | ((a) & y);
}

int f7(int n, int d){
    return (n << d)|(n >> (qq - d));
}

int f8(int n, int d){
    return (n >> d)|(n << (qq - d));
}

int f9(int x) {
  return (((0xffU << yy) & x) >> yy) | (((0xffU << xx) & x) >> zz) | (((0xffU << zz) & x) << zz) | (((0xffU) & x) << yy);
}

int f10(int x, int y) {
  return !!(x^y);
}

int f11(int x, int y) {
  int s = ((x ^ y) >> ww);
  int a = x >> ww;
  int u = ( ~ ((y + (~x + 1)) >> ww ) );
  return (!!(a&s)) | ( !!(u&(~s) ) );
}

int f12(int x) {
  return (!(( ~( x & (~x + 1)) | (0x01 << ww) ) & x)) & (~((!x << ww) >> ww));
}

int f13(int x) {
  return ( ( x | (~x + 1)) >> ww) & 0x01;
}

int f14(int x) {
  x ^= x >> xx;
  x ^= x >> zz;
  x ^= x >> 4;
  x ^= x >> tt;
  x ^= x >> 1;
  return x & 0x01;
}

int f15(int x) {
    return ((x >> ww) | ((~x + 1) >> ww)) + 1;
}

int f16(int x, int y) {
    while (y != 0){
        int a = x & y;
        x = x ^ y;
        y = a << 1;
    }
    return x;
}

int f17(int x){
    int m = 1;
    while (!(x & m)) {
        x = x ^ m;
        m <<= 1;
    }
    x = x ^ m;
    return x;
}

int f18(int x, int y){
    while (y != 0){
        int a = (~x) & y;
        x = x ^ y;
        y = a << 1;
    }
    return x;
}

int f19(int a, int b) {
    int c = 0;
    while (b > 0) {
         if (b & 1)
             c = c + a;

         a = a << 1;
         b = b >> 1;
     }
     return c;
}

int f20(int n){
    int a = (n << 4);
    a = a - n;
    return a;
}

int f21(int n){
    return ((n<<3) - n);
}

int f22(int n){
    int a, b;
    a = n % 10;
    switch (a) {
    case 0:
        b = 0;
        break;
    case 5:
        b = 1;
        break;
    default:
        b = -1;
    }
    return b;
}

int f23(int x, int n) {
  int a = x >> ww;
  int b = ((0x01 << n) + ~0x00)&a;
  int c = (~(!n) << ww) >> ww;
  int d = ((x + b) >> n);
  return (d & c) | (x& (~c));
}

void f24(size_t const x, void const * const y){
    unsigned char *b = (unsigned char*) y;
    unsigned char z;
    int i, j;

    for (i=x-1;i>=0;i--){
        for (j=7;j>=0;j--){
            z = (b[i] >> j) & 1;
            printf("%u", z);
        }
    }
    puts("");
}

int main(int argc, char* argv[]){
    if(argc==1 || argc > 3){
        return 0;
    }
    int a = f1(atoi(argv[1]));
    int b = f2(atoi(argv[2]));
    while(f14(a)){
        a = f19(a, tt);
    }
    b = f7(a, b);
    int c = f21(b);
    int d;
    if(f15(f18(c, a))){
        d = f20(c);
    }
    else{
        d = f21(c);
    }
    int e;
    if (f11(d, c)){
        e = f23(d, f17(a));
    }
    else{
        e = f3(d, f19(a, c));
    }
    int f = f16(f22(e), f9(e) );
    if(f4(f)){
        f = f5(f);
    }
    int g = f | e;
    int h = f6(f12(g), g, f19(g, tt));
    f24(sizeof(a), &h);
}
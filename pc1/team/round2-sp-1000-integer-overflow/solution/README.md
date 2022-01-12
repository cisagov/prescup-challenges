<img src="../../../pc1-logo.png" height="250px">

# + Integer * Overflow >>

In the files given, there is an overflow in file 1 on line 35. On this line, two integers are multiplied without checking to see if the result has overflowed and caused an unexpected result. 

Some might see an issue with file 2 line 23 as well, where 2 size_t variables are being added to the integer '1'. A key insight here is that these two size_t variables 
are being casted to the size_t type from the char type. In C on a 32 bit system, the size_t type will occupy 32 bits, and on a 64 bit system will occupy 64 bits.
In both cases, the char type is 1 byte in size. Because these variables are being cast from 1 byte to many more bytes, there is no chance of overflowing the calculation with addition.

[Here](https://github.com/python/cpython/pull/10174/commits/fe6b110919d72daf6a64e4d66d631504c72db378) is the exact
commit that fixed the bug in this version of the challenge.

## Flag

file1_35

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.

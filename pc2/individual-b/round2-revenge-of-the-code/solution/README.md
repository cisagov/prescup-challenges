# More Than Meets the Eye: Revenge of the Code Solution

This guide will demonstrate potential ways to solve each problem. 

## Unknown executable
The token for this part of the challenge can be found by simply running the `strings` command on the executable. It will be in the format of `here_is_your_token: <token>`. The necessary strings output will appear as the first readable line in the output and typically occurs at or around line 1638 of the output.

Output:

```
D$ $ <br/>
\$(3 <br/>
t$0H <br/>
here_is_your_token: grimwy42t0yc
/rustc/c7087fe00d2ba919df1d813c040a5d47e43b0fe7\src\libcore\macros\mod.rs
/rustc/c7087fe00d2ba919df1d813c040a5d47e43b0fe7\src\libcore\str\mod.rs
/rustc/c7087fe00d2ba919df1d813c040a5d47e43b0fe7\src\libcore\str\pattern.rs
```

## Reverse functionality
In this portion of the challenge, you are given an executable that will take a string as a command line argument and output another string. The executable shifts every character in the string up in the ASCII table by its index in the string (starting from 1). Every third character is also duplicated. For example, `abc` becomes `bdff`. 'a' is shifted up one to 'b', 'b' is shifted up two to 'd', and 'c' is shifted up three to 'f' and is then duplicated. The condensed ASCII table provided with the executable is normalized so that the character '0' has an adjusted ASCII value of 1. This will make wrapping ASCII values above 'z' (75 in this case) easier to reverse.

An easy way to determine the function is to enter a string made up of only one character, such as "aaaaaaaaaaaa", and then see how they shift. Once a pattern is recognized as occurring every 3 characters, enter a string of something like "abcabcabcabca" and see how it shifts. To prove the theory, try entering a string of "abcdefghijkl", and verify that everything changes as expected.

Example reverse process:
If the output string is `1wzz=fssh68805;;`, then you would perform the following functions to each ASCII character:

    1: subtract 1 = 0 <br/>
    w: subtract 2 = u <br/>
    z: subtract 3 = w <br/>
    z: remove as it is a duplicate <br/>
    =: subtract 4 = 9 <br/>
    f: subtract 5 = a <br/>
    s: subtract 6 = m <br/>
    s: remove as it is a duplicate <br/>
    h: subtract 7 = a <br/> 
    6: subtract 8 = y (6-6 = 0 and then 0-2 wraps back to value 74) <br/>
    8: subtract 9 = z (8-8 =0 and then 0-1 wraps back to value 75) <br/>
    8: remove as it is a duplicate <br/>
    0: subtract 10 = q (0-9 wraps back around to value 66) <br/>
    5: subtract 11 = u (5-5 = 0 and then 0-6 wraps back around to value 70) <br/>
    ;: subtract 12 = z (12-12 = 0, which wraps back to value 75) <br/>
    ;: remove as it is a duplicate <br/>

The resulting string would be `0uw9amayzquz`.

## RSA
The easiest way to solve this portion of the challenge is to write a Python script to reverse the encryption. All necessary values and functions for RSA are given. A message encrypted using RSA can be decrypted as follows: 
-  message = ciphertext<sup>d</sup> mod N 

Since these values are all given, there is no need to calculate them. The easiest way to decrypt the token is to iterate over the ciphertext string, apply the above formula to each character's value, and then convert the resulting ASCII value to the corresponding character. Some python code for doing so is [provided](./gold-rsa.py).

Once written and placed in the `/challenge/problem 3/` folder, this code can be tested with the provided `encrypted.txt` file as its command line argument. The [grading script](../grader.sh) will run the code against a separate piece of encrypted text in order to validate the code is working as expected. If the expected output matches the actual output, the token will be printed.

## Optimize

The provided Rust function used to calculate fibonacci numbers is far too slow to pass grading checks. More specifically, it has an exponential runtime. In order to pass the grading checks, your fibonacci `function.rs` code must be significantly faster. You must modify the current `functions.rs` file without changing the `main.rs` file in order to be graded successfully.

Multiple examples of optimized fibonacci functions can be found in this solution folder under the name [`function.rs.bck`](./solution/function.rs.bck), with the best of these being `fibo_optimized()`. It runs in linear time and will pass the grading checks. Update the `fibo_optimized()` function in the `function.rs` challenge file.

You can test this code on the local system by running `cargo run` in a terminal. Assuming `main.rs` is unmodified, it will print the elapsed time and output value from a handful of test cases run against your code. Run [`grader.sh`](../grader.sh) when you've completed both problems 3 and 4 to test for tokens. If all test cases run in under 250μs, the user will only receive the token for part 1. If they all run in under 25μs, the player will receive the tokens for both part 1 and part 2 for submission. 

## Answers:

Problem 1 - grimwy42t0yc 

Problem 2 - 0uw9amayzquz 

Problem 3 - 00kr0mtyyx0x 

Problem 4 Part 1 - gp8ka8cejms9

Problem 4 Part 2 - yfc2w44rpky5


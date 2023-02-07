# System Check

_Solution Guide_

## Overview

To begin, open the attached ISO (**first.c**, **second.py**, and **third.rs**) and examine the files. Each file contains the source code for a program that is being hosted remotely. Find a vulnerability in each one and exploit it.

The programs are accessible with `nc challenge.us 1234`, `nc challenge.us 1235`, and `nc challenge.us 1236`.

There are three submissions for this challenge. The submission fields have the labels "Program 1", "Program 2", and "Program 3", and these correspond to the same order as the ports shown above and solutions documented below.

Each submission is a 16-character lowercase hex string of the format `0123456789abcdef`.

## Question 1

_Program 1_

This program requires the user to exploit a very simple buffer overflow vulnerability.

The user is prompted for input into a buffer while the flag is loaded into a separate buffer. However, analysis of the code reveals that the buffer being used for input is part of a `struct`, in which the flag buffer immediately follows the input buffer. The `gets()` function is used to collect input, which is known to be vulnerable to buffer overflow exploits. Therefore, if the user enters enough characters into the input, `gets()` will begin to write characters into memory beyond the declared size of the array.

In this exercise, that means those characters are written into the flag buffer before the flag is written to it, and `gets()` will only put a NULL terminator at the end of the user's input. The solution, then, is to input at least 128 plus the flag length junk characters -- preferably characters which are not going to be used in the flag. Around 150 characters will be sufficient, and then the program will echo the user's input back (now with the flag having overwritten a part of it).

```bash
python3 -c "print('p'*150)" | nc challenge.us 1234
```

## Question 2

_Program 2_

This program requires the user to exploit a program vulnerable to SQL injection.

The user is initially prompted for a username and password. The program then goes to do a lookup in its local SQLite database to find if such a user exists, and if so to retrieve its hashed password (with salt).

While it is not explicit to the competitor, brute force is not a viable solution here. Instead, the competitor should note that the `WHERE` clause does not sanitize the username input. This is a major vulnerability in the program, and it can be exploited.

In order to craft the exploit, it's important to examine the expected result from the query. Fortunately, the result is expected to be in the form of a tuple (username, stored_hash, salt). The password that the user entered previously is then hashed using the stored salt, and the new hash is compared to the stored hash. If they match, the username is printed again. Note that the printed username is actually a value returned from the database, ***not*** the username provided initially.

This means that if the query can be engineered such that the flag is in the first column, a hashed password is in the second column, and a salt is in the third column, a successful login will print the flag.

```
a' UNION SELECT *, '2a107a25285e89b2cdd70c57294db90f5ca76b04e97c1676d3b46de4bab9da5d' as Col2, '11bba653b4f576becdd0911bcc11c058111f1b4ad41cf2c0618bdafc798d8ca6' as Col3 from flag'
```

Giving the above as the username and the letter 'a' as the password retrieves the flag from the database. The `UNION` statement above will treat the `flag` table as an extension of the `users` table. However, the `flag` table only has one column -- but it's possible to add custom columns with the `as` keyword.

So in order to successfully login, run the same hashing algorithm as shown in the exercise with your own chosen password and salt. The above solution uses the hash of the letter 'a' with a randomly-chosen salt. The program is tricked into believing that it has successfully retrieved the user from its database, and compares the password entered by the user to what it believes was retrieved from the database -- thus enabling a successful login without an existing account.

## Question 3

_Program 3 (contents of a flag.txt file)_

This program looks intimidating because it seems like an exploit can be lurking anywhere. It requires the competitor to understand the concept of directory traversal. The program is actually not so difficult to trick.

Upon interacting with the program, the user can attempt to login or register.

Choosing to register enables the user to create an account without any restriction. Once the account is created, the user can immediately login with the same credentials. Once logged in, the program prompts the user with more actions -- changing the password, changing the user's profile picture, and viewing the user's profile picture.

Choosing to view the profile picture will actually just print the contents of the file. Examining the code reveals that the profile pictures are `svg` files all stored in an `images` directory. Further examination reveals that the user's profile picture filename is not validated or sanitized. This enables an exploit -- change the user's profile picture to a custom value and enter `../flag.txt`. Then view the picture again, and it will print the flag.

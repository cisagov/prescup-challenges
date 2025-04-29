# va_list Adventure

Clumsy Coder Cody has started developing an adventure game in the `C` programming language, and after giving it to a friend for testing, an exploit was discovered!  However, Cody's friend must have been in a hurry because he only provided minimal guidance to find and resolve the issue.

**NICE Work Roles**

- [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Vulnerability Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform penetration testing.
- [T1118](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify vulnerabilities.

## Background

Clumsy Coder Cody sent you the following email:

```none
Hey!

A buddy of mine was able to extract a secret value from a text adventure 
game I'm making in `C`. When I asked how he did it, all he would say was 
"Leak the stack, use that to leak the globals, done, EZPZ". 

I don't understand any of that, and I just want to fix my game. 
Can you help me by recreating his exploit?

P.S. I put my code on `challenge.us` for you to download! You're welcome!

- Clumsy Coder Cody
```

## Getting Started

Log in to the provided Kali VM and access the adventure game using `nc exploit.us 31337`. You can download the executable and source code from `challenge.us`.

## Submission

There are 3 tokens to retrieve in this challenge. Each token is a 12-character hexadecimal value. Tokens 1 and 2 are retrieved by running a grading check on `challenge.us`, while Token 3 will be recovered directly from the vulnerable program's memory.

- Token 1: Discover the vulnerability on `exploit.us` on port `31337` and use it to leak the address of `char playerName[100]` in `main` and enter it in the grader at `challenge.us`.
    - The address changes after each run of the game.
- Token 2: Exploit the game at `exploit.us` on port `31337` to leak the address of the global `character player` and enter it in the grader at `challenge.us`.
    - The address changes after each run of the game.
- Token 3: Exploit the game at `exploit.us` on port `31337` to retrieve the secret token stored in the `globalStr` global variable. Submit this token directly on this page.


## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-valist|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.
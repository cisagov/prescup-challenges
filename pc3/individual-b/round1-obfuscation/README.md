# Obfuscation Ain't All It's Cracked Up To Be

Intercept communication between local client programs and a remote server by decompiling .NET assemblies.

## Background

  We've discovered some very suspicious executables communicating with a server over the Internet. It appears that the executables receive some encoded data each time, but we have no idea what that data is. Your task is to figure out how to decode this data and find out what it is.

## Getting Started

  The challenge files are in the `challenge` folder. You will need to decompile these files in order to understand how to decode the two challenge tokens. The challenge was designed to be completed on Windows.

## Submission

  There are two tokens in this challenge. The `prescup3-b04-cs1.exe` executable is receiving the first token, and `prescup3-b04-cs2.exe` receives the other one. For the open-sourced version, both executables will have their original tokens replaced with the string "Success".

## Server

  For the open sourced version of this challenge, you will also need to run the server on your local system. See `server/README.md` for more information.

## Source

  The source code for both of the challenge programs is located in `solution/source`. It has been slightly modified to build the version of the executables in this repository. The original code is commented out. The executables were originally obfuscated with CSharpObfuscator, but this step will not be necessary. Instead, you can open each solution file in Visual Studio 2019 (other versions may work) and build each one.
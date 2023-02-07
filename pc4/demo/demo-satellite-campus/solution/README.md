# Satellite Campus

_Solution Guide_

## Overview

In this challenge, players get acquainted with a number of tools that can be used throughout the competition, as well as perform necessary tasks such as network scanning, password spraying/brute forcing, and binary analysis to answer the challenge questions.

## Question 1

_What additional program was developed by the NSA as a reverse engineering tool?_

The `tools_README.txt` has a large list of tools. A Google search similar to “NSA reverse engineering tool” should provide the tool `Ghidra` as a result.

Submit `Ghidra` as the answer to Question 1. 

## Question 2

_What python library is a CTF framework and exploit development tool?_

A Google search similar to  “python library CTF framework and exploit development tool” should provide `pwntools` as as result.

Submit `pwntools` as the answer to Question 2. 

## Question 3

_What service is the satellite running?_

`nmap` is a service scanning tool that will reveal which services/ports a remote system has open. 

Perform an `nmap` scan of the satellite. 

In a terminal, type `nmap satellite-1337`. On the system, `satellite-1337`, only one port will be listed as open: port 22. Next to the open port listed in the output of `nmap`, the service will say ssh. `ssh` typically runs on TCP port 22. 

Submit `ssh` as the answer to Question 3. 

## Question 4

_What is the test user's password?_

1. Make a wordlist of all the planets in our solar system. Create a text file called planets.txt that contains the following (each separated by a new line):
```
mercury
venus
earth
mars
jupiter
saturn
neptune
uranus
```

2. Run the command `hydra -l test -P planets.txt satellite-1337 ssh`. Hydra will tell you the correct password, `jupiter`.

Submit `jupiter` as the answer to Question 4. 

## Question 5

_What is the token in the binary?_

1. Download the `space_question` and `pwn_space.py` files using scp: `scp test@satellite-1337:space_question space_question`.  
2. Run Ghidra by typing `ghidra` into the command line. This will open a window and start the application for you. 
3. Click “File” and “New Project” to create a new project. 
4. Choose “Non-Shared Project”, and name your project. Then, drag the `space_question` file into the folder of your new project in the Ghidra window. 
5. A prompt will appear asking what format you wish to see the file in, what language the file is written in, where you want to store this file, and what the file is called. Fill these out as necessary, then double click the `space_question` file within Ghidra. 
6. When Ghidra asks to analyze the binary, click “Yes”, then “Analyze” (you may have to re-size the window to click analyze). This will decompile the binary into human readable code.
7. Follow the challenge instructions. The function we want to jump to is called `print_flag`. The address for the `print_flag` function will be `0x080491a6`. 
8. To get the final question, just put the address of the `print_flag` function in place of `0xdeadbeef` in the `pwn_space.py` script.


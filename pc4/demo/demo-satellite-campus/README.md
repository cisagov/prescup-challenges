# Satellite Campus

Hi there Captain,

Going on an adventure through space? The Dauntless is a heck of a ship - I think you are going to love it. I can only imagine what you are going to see out there. You’ll bring back some souvenirs for the rest of us, right?

Anyway, my job is to help you get acquainted with some of the tools you’ll be using on your adventure. I sent a satellite into orbit the other day, and we are going to hack it! It’ll be fun, trust me.

**NICE Work Roles**
- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation+Analyst&id=All)

**NICE Tasks**
- [T0641](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0641&description=All) - Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.
- [T0736](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0736&description=All) - Lead or enable exploitation operations in support of organization objectives and target requirements.

## IMPORTANT

This challenge is only partially open sourced. The files in the [challenge directory](./challege) are provided to give you a starting point if you wish to recreate the challenge on your own. The full challenge can be played on the hosted site. 

## Getting Started

You'll have to perform several tasks on a Kali Virtual Machine (VM) to solve this challenge. Details on each task are provided here, and a list of Challenge Questions is below this section. 

1. Check out some of the tools on the Kali VM. On the desktop, there is a file called `tools_README.txt`. Please give that a look, and answer the first two Challenge Questions.
2. Use `nmap` to scan my satellite and find the service that it is running to answer Challenge Question 3. DNS and DHCP are handled in the background, so you can use the target's hostname: `satellite-1337`. 
3. The username for the satellite is: `test`. What's the password? I'm not telling you! I'll give you a hint though: it's one of the planets in our solar system, all lowercase. A tool you might want to check out is `hydra`. See if you can figure out how it works and answer Question 4.
4. `ssh` over to the satellite (you did solve Q3, right?). You will find two files on there. A 32 bit binary, and a python pwntools file. Use `scp` to copy those files back to your Kali machine. We are going to complete the pwntools script.  

    a. We are going to reverse engineer the binary. Please boot up `ghidra` and set up a new project (you may need to re-size some windows to click buttons in the UI).  
    b. Import the space_question binary into your project. After ghidra analyzes the binary, we can see it's assembly code, as well ghidra's attempt to de-compile the code.  
    c. In the `Symbol Tree` menu on the left, find the folder called functions. Open it and find `main`. You will see that main just calls another function, named `start`.  
    d. Double click on `start()` to jump to that function. You will see that it just prints a question, calls `fgets()` then exits. Notice that `fgets` takes in a much larger input than the local_18 buffer allows. This will cause a buffer overflow. We want to overflow the buffer, take control of the instruction pointer, and re-direct it to a function we want to run. 
    e. I have the exploit already set up in the pwn_space.py file. All we need to do now is find where to jump to. Where do we want to go? That's for you to find out. See if there are any interesting functions.  
    f. Once you find an interesting function, look for its address. It should be the first instruction, which is `PUSH EBP`. As a hint, The address ends in `a6`.  
    g. Now we can finish the `pwn_space.py` script. I already found where the buffer overflows, but feel free to play around with that if you'd like. All you have to do is replace the `0xdeadbeef` with the address of the target function.  
    h. Please run the python script, and find the token! Note, you might have to press enter after the pwn script switches to interactive mode in order to read it.

Best of luck on your mission!

## Challenge Questions

1. What additional program was developed by the NSA as a reverse engineering tool?
2. What python library is a CTF framework and exploit development tool?
3. What service is the satellite running?
4. What is the test user's password?
5. What is the token in the binary?

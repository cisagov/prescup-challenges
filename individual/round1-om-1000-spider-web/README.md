<img src="../../logo.png" height="250px">

# Spider Web
#### Category: Operate and Maintain
#### Difficulty Level: 1000
#### Executive Order Category: Reverse Engineering

## Background
Your director's Windows computer had its data stolen by some malware. However, the malware author has been surprisingly
generous - if you can find the hidden key within the program and then run the program from the desktop with that key, it
will give you the flag. But beware... if the program detects that you are meddling with it, bad things may happen. If
you supply the wrong key, then you need to reboot the system and re-run the program to get it to print the flag after
supplying the correct key.

## Getting Started

This challenge has been recompiled in order to generate debug symbols for the solution guide. The executable should be
analyzed in a malware analysis environment - a Windows VM with IDA is likely plenty, but you may use whatever tools you
like.

The executable does not do anything dangerous, but heuristic detection will likely flag some of its behavior as
malicious.

There are a couple of important details to note before beginning. There are several anti-debugging tricks being used in
this executable. There are timing checks, a custom structured exception handler (SEH), and functions that check for the
presence of debuggers.

Once you find the `main()` function, you have a base to figure out the flow of execution.

You will need to configure your debugger to pass exceptions to the program in order to complete this challenge.

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.
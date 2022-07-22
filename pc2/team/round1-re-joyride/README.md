# Reverse Engineering Joyride

## Note

The following challenge guide is only slightly modified from the 2020 President's Cup Competition. You will need to run the challenge server in order to play the challenge. See [server/README.md](server/README.md) for more information. The client program [challenge/re-joyride.exe](challenge/re-joyride.exe) has been modified to connect to the server running locally.

## Challenge Overview

In this challenge, you will do some light software reverse engineering (with fairly little assembly knowledge required)
to discover what Microsoft API functions a piece of software is calling as part of its communication with a remote
server program. You will then need to use this discovery to hook a subset of these functions using a provided trimmed
copy of the Detours library with a provided example and some starting code.

**NICE Work Roles:**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation+Analyst&id=All)

**NICE Tasks:**

- [T0736](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0736&description=All): Lead or enable exploitation operations in support of organization objectives and target requirements.

- [T0641](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0641&description=All): Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.

- [T0720](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0720&description=All): Identify gaps in our understanding of target technology and developing innovative collection approaches.

## Background

You will need to understand the concept of how a program interacts with a dynamically-linked library (DLL), to the
extent of viewing what functions the program is using from a DLL. You will also need to be able to get an idea of how a
Microsoft API function works from Microsoft's documentation, such as
[this](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowexa).
Finally, you will also need to understand the concept of hooking functions to intercept (and log) the function's
arguments.

## Getting Started

The [challenge folder](challenge) contains the files given during the competition. It contains the challenge executable file as well as a trimmed down copy of the official Detours repository. The Detours library is already built for you.

The folder structure includes the simplest example in the official repository for convenience. Feel free to go examine
the actual repository on GitHub, but there is far more information than you'll need or want to sift through.

The first thing you will probably try to do knowing that there is client/server communication in this challenge is
run the given client and examine the traffic in Wireshark. Do so, and consider why the traffic looks like that.

Next, you'll want to see if this program is using any Microsoft API functions that would explain the traffic. IDA is one
possible tool that will give you this information, but not by any means the only one. The program does use some
Microsoft API functions, and you should identify more than one. Have a look at the Microsoft documentation for all of
the functions you find, paying special attention to any function arguments you would like to examine.

Now open the provided Detours folder and navigate to `\Detours trimmed\samples\prescup`. Open `prescup.cpp` in whatever
editor you like. In this file, you will define hooks for the functions you found. Have a look at
`\Detours trimmed\samples\simple\simple.cpp` for an example of this being done with another function.

Once you're ready to compile your DLL, open the Start menu and do a search for
`x64 Native Tools Command Prompt for VS 2019`. Open it and navigate it to your `\Detours trimmed\samples\prescup`
folder, and then type `nmake`. Assuming your code is written correctly, it will compile and create a new
`prescup64.dll` in `\Detours trimmed\bin.X64`.

Open a separate, non-developer, Powershell or Command Prompt window and navigate to the `bin.X64` folder. Enter
`.\withdll.exe /d:prescup64.dll C:\Path\To\prescup-t7-r1.exe` (obviously, entering the actual path to the challenge
executable). Once the process finishes, there will be a `prescup.log` in this folder, assuming that you used the
provided `Log()` stream in `prescup.cpp`.

## Winning Conditions

In `prescup.log` will be the output that you dumped during the challenge. Assuming that you've done everything
correctly, there will be two separate flags in this file. They will have the format `prescup{0123456789abcdef}`.
There will be one flag sent from the client to the server, and another flag that the client receives from the server.

## Submission Guidelines

You can submit the whole flag including the prescup wrapper, like this: `prescup{0123456789abcdef}`.
Remember to make sure that you supply each flag in the correct box.

### Hints

When you create your hook functions, make sure to add an indication to the log message which direction traffic is
flowing so that you know which flag came from the client, and which came from the server.

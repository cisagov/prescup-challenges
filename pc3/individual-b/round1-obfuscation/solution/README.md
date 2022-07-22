# Obfuscation Ain't All It's Cracked Up To Be Solution

1. (Optional) Start a packet capture and run each executable to see that the traffic is encrypted.
1. Create two new folders on the Desktop, `cs1` and `cs2`.
1. Open a Powershell prompt and navigate to each of the folders you just created and run `dotnet new console`. Leave Powershell open.
1. In the start menu, search for dotPeek and run it.
1. (Optional) Go to Tools -> Options, switch to the Decompiler tab, and uncheck "Use sources from symbol files when available", and save.
1. Click Open Folder in dotPeek and open the folder into which you extracted the contents of the challenge zip.
1. There will be two entries of `prescup3-b04-cs1` and two of `prescup3-b04-cs2`. For each, one will say "not supported", and that entry can be ignored.
1. The remaining entries will have arrows to expand for more information. Expand each, and then under `prescup3-b04-cs1` expand `H` and `j`, and under `prescup3-b04-cs2` expand `g` and `MV`.
1. Under these expanded entries are the methods in each program. We're going to recompile both programs by adding code to print their respective flags.
1. In the `cs1` folder you created earlier, open Program.cs in any editor and delete the existing code.
1. For the `prescup3-b04-cs1` program, double-click any of the methods under H, wait for the code to display, and then copy all of the code, and paste it into the open Program.cs file.
1. Double-click any method under `j` and wait for the code to display. Copy from `internal class j` to the second-to-last `}`. Paste this just before the last `}` in the open Program.cs.
1. Add `using System.Runtime.Serialization.Formatters.Binary;` just under the other `using` statements near the top of the file, and save the file (keep it open).
1. (Optional) Back in the Powershell prompt from earlier, enter the `cs1` folder and type `dotnet build`. If the build fails, check the copying steps above or use the solution file provided here.
1. Add `using System.Text;` just under the other `using` statements.
1. Add `var ascii = new ASCIIEncoding(); Console.WriteLine(ascii.GetString(M, 0, M.Length));` at the end of the `u()` method in Program.cs.
1. In the Powershell prompt, enter the `cs1` folder and type `dotnet run`. If everything is done right, you should receive the first flag.
1. Repeat steps 11 through 16, for `cs2`. When copying from `MV.cs`, start the copy from `internal class MV`. In `cs2/Program.cs`, also add `using System;` in addition to the previous `using` statements.
1. (Optional) Repeat step 15 for `cs2`.
1. Add `var ascii = new ASCIIEncoding(); Console.WriteLine(ascii.GetString(numArray2, 0, numArray2.Length));` at the end of the `C()` method.
1. Repeat step 18 for `cs2`, and you should get the second flag.

## Alternative

  In the `cs1` and `cs2` folders are the respective solution `Program.cs` files for each executable.

## Setup

  You will need .NET 5.0 installed on your system. It should be available [here](https://dotnet.microsoft.com/en-us/download/dotnet/5.0).

## Source

  The `source` folder contains the source code for the open sourced version of this challenge, with some comments indicating changes made to make the challenge executables attempt to connect to a server running locally. The executables originally used an obfuscation tool, but the original obfuscation has been left as much as-is as possible, aside from the connection changes.
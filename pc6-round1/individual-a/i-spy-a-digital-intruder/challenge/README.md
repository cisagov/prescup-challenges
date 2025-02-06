# I Spy: A Digital Intruder

*Challenge Artifacts*

- [variant1](./variant1/) - This folder contains all of the files for variant 1.
- [variant2](./variant2/) - This folder contains all of the files for variant 2.
- [variant3](./variant3/) - This folder contains all of the files for variant 3.
- [variant4](./variant4/) - This folder contains all of the files for variant 4.
- [chk1](./chk1/) - This is the source code for the `chk1.dll`.
  - This project requires the .NET 6.0 SDK
  - You can build this project by running the following command from the root of the source code directory:
  - `dotnet build -c Release`
- [chk2](./chk2/) - This is the source code for the `chk2.dll`.
  - This project requires the .NET 6.0 SDK
  - You can build this project by running the following command from the root of the source code directory:
  - `dotnet build -c Release`
- [fschecker](./challenge-server/src/fschecker/)  - This is the source code for the `fschecker` executable.
  - This project requires the .NET 6.0 SDK
  - You can build this project by running the following command from the root of the source code directory:
  - `dotnet build -c Release`

- `compromised-host`:
  - [Module1.Macro.txt](./compromised-host/Module1.Macro.txt) - This is the macro code that is embedded in the [Budget Proposal.odt](./compromised-host/Budget%20Proposal.odt) Libre Office document.
  - [Budget Proposal.odt](./compromised-host/Budget%20Proposal.odt) - This file contains a macro that downloads the `fschecker` executable.
  - [Q1 Sales Data.ods](./compromised-host/Q1%20Sales%20Data.ods) - This spreadsheet file contains the images on tab5 used to find the bitcoin address in question 4.
  - [networksvcs.py](./compromised-host/networksvcs.py) - This file checks for the presence of the `fschecker` executable and runs it if present.
    - [sysntwrk.service](./compromised-host/sysntwrk.service) - The service that runs `networksvcs.py`.

- `kali-wan-webserver`:
  - [loader.unencoded.txt](./kali-wan-webserver/loader.unencoded.txt) - This is a base64 decoded version of [loader.txt](./kali-wan-webserver/www/html/ed209rbcptr8tor/loader.txt) for reference purposes.
  - [loader.txt](./kali-wan-webserver/www/html/ed209rbcptr8tor/loader.txt) - This is a base64 encoded text file that contains python code that tries to execute the `fschecker` executable. Refer to [loader.unencoded.txt](./kali-wan-webserver/loader.unencoded.txt).

# I Want to Play a Game

*Challenge Artifacts*

- `passwordHash-v[1-4].txt` - Password hash files for the 4 different variants of the challenge.
- [wordlist.txt](./wordlist.txt) - This is a wordlist that is attached to the cdrom drive of the competitor kali boxes

- `web-api`:
  - [GameAPI](./web-api/GameAPI/) - This is the source code for the .NET `GameAPI` web API application.
    - This project requires the .NET 6.0 SDK
    - You can build this project by running the following command from the root of the source code directory:
    - `dotnet build -c Release`
  - [kestrel-gameapi.service](./web-api/kestrel-gameapi.service) - The service that runs the GameAPI web application running at `http://10.7.7.210/swagger/index.html`.

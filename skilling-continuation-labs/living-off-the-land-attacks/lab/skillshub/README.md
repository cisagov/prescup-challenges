# Skills Hub Artifacts
_List of artifacts and their descriptions/use_

 - [logInjection.sh](./logInjection.sh): Bash script that reads GuestInfo variables and injects as a Syslog entry.
   - [logInject.service](./logInject.service): Service to run the `logInjection.sh` script.
   - [logInject.timer](./logInject.timer): Controls how often the script is run.

 - [mini-challenge.py](./mini_challenge.py): Connects to a remote system and runs a basic PowerShell command.
   - [mini-challenge.service](./mini-challenge.service): Service to run the `mini-challenge.py` script.
   - [mini-challenge.timer](./mini-challenge.timer): Controls how often the script is run.


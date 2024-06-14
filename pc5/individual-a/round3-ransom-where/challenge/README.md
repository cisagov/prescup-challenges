# Ransom Where?

_Challenge Artifacts_

[attacker](./attacker/)
- [main](./attacker/dist/main) - This is the main file that when executed runs the ransomware when not compiled. All other files in the directory are required to create the compiled ransomware executable. Executable is created with `pyinstaller` and on the `attacker` VM the file is located at `/home/user/.zlogin`.

[website](./website/)
- [main.py](./website/main.py) - This file is called to handle running the website. All other files in the folder are required for the website to run correctly.
- [database.db](./website/database.db) - This file is a sqlite3 database that holds information that is used by the website.
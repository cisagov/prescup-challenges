# Logic Zero
_Challenge Artifacts_

These artifacts are placed on the attacker machine.

- [clicker.sh](./attacker/clicker.sh): Uses Firefox to login to the zero trust application with the compromised credentials.
- [convert_cookies.py](./attacker/convert_cookies.py): Extracts cookies from Firefox to use curl commands with the same cookie to bypass authentication.
- [curler.sh](./attacker/curler.sh): Performs curl requests with a lot of fluff and few helpful results.
- [curler-cgi.sh](./attacker/curler-cgi.sh): Performs curl requests against within the cgi-bin directory.
- [final.sh](./attacker/final.sh): Performs the final attack and infects the target with a malicious service.
- [attacker.sh](./attacker/attacker.sh): Ensures all five scripts above are executed in the correct order.
- [attacker.service](./attacker/attacker.service): Executes the `attacker.sh` as a systemd service.
- [tsyslog](./attacker/tsyslog): Fake syslog script. It is a real logic bomb. Be careful!
- [tsyslog.service](./attacker/tsyslog.service): Fake syslog service. It executes the tsyslog logic bomb as systemd service.

These artifacts are placed on the pritunl machine.
- [agent-maker.sh](./pritunl/agent-maker.sh): Creates agent-001 through agent-469. One of them will have a very weak password.
- [agent-maker.service](./pritunl/agent-maker.service): Executes the agent-maker.sh as a systemd service.
- [pritunl-zero](./pritunl/pritunl-zero/): This folder contains the files needed to restore the pritunl-zero database to an existing MongoDB database server. Use a command similar to the following: `mongorestore -d <database_name> <directory_backup>`. For example: `mongorestore -d pritunl-zero pritunl-zero`.  

These artifacts are placed on the webserver machine.
- [cgi-mover.sh](./webserver/cgi-mover.sh): Renames the .cgi file
- [cgi-mover.service](./webserver/cgi-mover.sh): Executes the cgi-mover.sh as systemd service
 

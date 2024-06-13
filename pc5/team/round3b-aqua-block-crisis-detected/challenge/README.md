# Aqua Block Crisis Detected

_Challenge Artifacts_

- challenge-server
  - [gradingScript.py](./challenge-server/gradingScript.py) - This grading script runs to grade the environment when the challenge is deployed in the hosted environment. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge. 

- attackerSystem
  - [anacron](./attackerSystem/anacron) - Script with methods to xor encode and decode data.
  - [anacron-prep.sh](./attackerSystem/anacron-prep.sh) - Script with methods to xor encode and decode data that is used to create evidence of the hacker's presence.
  - [attack.service](./attackerSystem/attack.service) - Service configuration file for the attack.sh script.
  - [attack.sh](./attackerSystem/attack.sh) - Script used to mimic the hacker's activities.

- mailServer
  - [boxer-sent.sh](./mailServer/boxer-sent.sh) - Parses email file and adds data to sent_archive.
  - [boxer.sh](./mailServer/boxer.sh) - Parses email file, manipulates data and adds file to appropriate mailboxes.
  - [date-swapper.sh](./mailServer/date-swapper.sh) - Script to change dates on specified file.
  - [deploy.service](./mailServer/deploy.service) - Service configuration file for the deploy.sh script.
  - [deploy.sh](./mailServer/deploy.sh) - Script to change log file permissions and user mallory's mail directories.
  - [keygen.sh](./mailServer/keygen.sh) - Script to write a secret key to a file.
  - [working.txt](./mailServer/working.txt) - Email file.

- openplcServer 
  - [deploy.service](./openplcServer/deploy.service) - Service configuration file for deploy.sh script.
  - [deploy.sh](./openplcServer/deploy.sh) - Script to change a password.

- rapidScadaServer
  - [dam.zip](./openplcServer/dam.zip) - Collection of scada server configuration files.

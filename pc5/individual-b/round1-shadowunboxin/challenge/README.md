# Shadowunboxin

_Challenge Artifacts_

- [challengeserver](./challengeserver/)
  - [checkMessages.py](./challengeserver/checkMessages.py) - Python script that is used to validate/check for email messages containing the expected malicious link.  
  - [getMessages.py](./challengeserver/getMessages.py) - Python script that parses the contents of the inbox directory into individual email messages.
  - [gradingScript.sh](./challengeserver/gradingScript.sh) - This grading script runs to grade the environment when the challenge is deployed in the hosted environment. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
  - [inbox](./challengeserver/inbox) - Example of email inbox content.
  - [infect.sh](./challengeserver/infect.sh) - Downloads and executes `payload.elf` file.

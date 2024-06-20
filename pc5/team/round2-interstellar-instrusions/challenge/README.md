# Interstellar Intrusions

_Challenge Artifacts_

Due to the nature of the challenge, none of the required tasks can be completed without the virtual challenge environment. The following artifacts are provided as offline resources only.

Challenge Server Scripts and Required Files
- [gradingScript.sh](./challengeserver/gradingScript.sh) -- performs the checks to ensure the proper email has been received and initiates the simulated user action on the User systems. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [getMessages.py](./challengeserver/getMessages.py) -- parses the inbox file retrieved by the grading check and gets distinct messages and puts them in their own directory for checking. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [checkMessages.py](./challengeserver/checkMessages.py) -- checks the contents of the messages output by the above script and validates they have passed the challenge conditions. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [infect.sh](./challengeserver/infect.sh) -- is run via SSH against the User system to perform the simulated user actions, once the above grading script has verified the accuracy of the phishing email. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [webserver.py](./webserver.py) -- Provides a template for a webserver to host a payload file and trigger a download automatically upon accessing a page


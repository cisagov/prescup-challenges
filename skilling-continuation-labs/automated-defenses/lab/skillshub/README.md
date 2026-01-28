# Skills Hub Artifacts
_List of artifacts and their descriptions/use_

[grading.py](./grading.py):
 - [dos.sh](./dos.sh) - The script used to generate the denial of service traffic during the mini-challenge.
 - [grading.py](./grading.py) - the grading script used by the Skills Hub to validate tasks are completed successfully.
 - [mini1.sh](./mini1.sh) - One of four email scripts used by the mini-challenge. Ties to the threat actor Crimson Viper.
 - [mini2.sh](./mini2.sh) - One of four email scripts used by the mini-challenge. Ties to the threat actor Silent Raven.
 - [mini3.sh](./mini3.sh) - One of four email scripts used by the mini-challenge. Ties to the threat actor Feral Wolf.
 - [mini4.sh](./mini4.sh) - One of four email scripts used by the mini-challenge. Ties to the threat actor Burning Mantis.
 - [startup.sh](./startup.sh) - The startup script used by the Skills Hub. The script triggers. afew SSH logins, email messages, and sqlmap commands to stage logs in the honeypot at lab start. 
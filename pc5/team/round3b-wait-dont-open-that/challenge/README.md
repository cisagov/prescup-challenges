# Wait, Don't Open That!

_Challenge Artifacts_

kali
- [kali/*](./kali/) - This is the collection of documents that users must analyze.
- [kali/freescan_source](./kali/freescan_source/) - The source code for the freescan app that is appended to the [hacked_user_accounts.pdf](./kali/hacked_user_accounts.pdf) file.
- [kali/NetworkMonitorApp_source](./kali/NetworkMonitorApp_source/) - The source code for the [NetworkMonitorApp.dll](./kali/NetworkMonitorApp.dll) that users must decompile and examine.

challenge-server
- [challenge.-server/gradingScript.py](./challenge-server/gradingScript.py) - This grading script runs to grade the environment when the challenge is deployed in the hosted environment. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge. 
- [challenge-server/file_encryptor](./challenge-server/file_encryptor) - This executable is called by the [startupScript.sh](./challenge-server/startupScript.sh) to encrypt one of the token character strings.
- [challenge-server/file_encryptor_source](./challenge-server/file_encryptor_source/) - The source code for the [file_encryptor](./challenge-server/file_encryptor) that is called by the [startupScript.sh](./challenge-server/startupScript.sh). 

webserver
- [webserver/](./webserver/html/) - The contents of this folder is hosted in `/var/www/` of the web server. 

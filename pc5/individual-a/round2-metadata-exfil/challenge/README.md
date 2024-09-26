# Meta Data Exfil

_Challenge Artifacts_

- [startup.sh](./challengeserver/startup.sh) -- handles all of the artifact setup for the challenge and configures the web server. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge. The script assumes that Apache is installed and running a web service on the localhost.
- [challenge site files](./challengeserver/challenge-site-files) -- includes all of the pdfs that will be present in the recovered_files.zip file provided at challenge.us.
- [stellaris spacecraft](./challengeserver/challenge-site-files/stellaris_spacecraft) -- includes 9 pdfs, the only difference between them being the password value inside. The file chosen for use is determined by the index value randomly selected at deployment. The selected file is included in the recovered_files.zip file provided at challenge.us.
- [mysterious object](./challengeserver/mysterious-object) -- the second token is added to mysterious_object.pdf, then zipped into the docx file. It is then encoded. The file is then added to the webroot of the website.
- [delidian](./challengeserver/delidian) -- the password for a zip that holds delidian_machine.pdf is added to delidians.txt, which is then put through a hex dump and caesar cipher. The file is then added to the webroot of the website.

_Competitor Artifacts_

In lieu of accessing the virtual challenge environment, you can solve the major tasks of the challenge with the artifacts below. An answer key is available [here](./competitor/answers.md).

- [recovered_files.zip](./competitor/recovered_files.zip) -- the set of recovered files provided via challenge.us per the challenge guide. This zip file is required to answer question 1.
- [webroot.zip](./competitor/webroot.zip) -- the webroot of the target website in the challenge. The webroot contains the necessary files for questions 2 and 3.



# Different Lens

_Challenge Artifacts_

The artifacts below would allow you to recreate the challenge on an Apache webserver. Note that you may need to modify certain aspects to fit your environment. These scripts may not operate as intended unless run with a VM configuration that mirrors what is in the hosted challenge.

- [place1.sh](./webserver/place1.sh) -- Sets the first token and creates the artifact for solving question 1.
- [place2.sh](./webserver/place2.sh) -- Sets the second token and creates the artifact for solving question 2.
- [place3.py](./webserver/place3.py) -- Sets the third token and creates the artifact for solving question 3.
- [place4-1.sh](./webserver/place4-1.sh) -- Sets the fourth token (part 1) and creates the artifact for solving question 4.
- [place4-2.sh](./webserver/place4-2.sh) -- Sets the fourth token (part 2) and creates the artifact for solving question 4.
- [place-tokens.sh](./webserver/place-tokens.sh) -- Calls each script above to set each token.
- [place-tokens.service](./webserver/place-tokens.service) -- Calls place-tokens.sh as a service.
- [html.zip](./webserver/html.zip) -- This is the content of the website. Extract and place as /var/www/html. The setup scripts will generate and modify the contents as needed.

_Competitor Artifacts_

In lieu of accessing the virtual challenge environment, you can use the file below to solve the challenge in a similar but offline format. The webroot directory includes all of the files needed to solve the challenge in the absence of the webserver/website. An answer key can be found [here](./competitor/answers.md)

- [webroot.zip](./competitor/webroot.zip) -- the webroot of the web site in the challenge. Contains all of the artifacts needed to solve the challenge offline.

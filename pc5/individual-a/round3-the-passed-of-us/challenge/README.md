# The Passed of Us

_Challenge Artifacts_

Challenge Server Scripts and Required Files
- [setup.sh](./challengeserver/setup.sh) -- handles all of the artifact setup for the challenge and adds/moves the required files to the webserver and hosted_files directory. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [encrypt.py-files](./challengeserver/encrypt.py-files/) -- includes the five encrypt.py files used by the challenge server to dynamically create the password vault for each gamespace. The script used is determined by the index value selected at deployment. These may not operate as intended unless run with a VM configuration that mirrors what is in the hosted challenge.
- [registries](./challengeserver/registries/) -- inlcudes the five registry files used by the challenge server to dynamically add the vault inforamtion for the target user. The initial registry file is determined by the index value selected at deployment.
- [credentials](./challengeserver/credentials) -- the dynamically generated password is substituted into this file and then is encrypted as the password vault
- [secrets.csv](./challengeserver/secrets.csv) -- the dynamically generated token is substitued into this .csv and then it is copied to the webserver's webroot directory for use by the secrests site.
- [webroot.zip](./challengserver/webroot.zip) -- the initial webroot files before the script dynamically alters them.

Competitor Artifacts

In lieu of accessing the challenge's virtual environment, you may use the artifacts listed below to conduct the major tasks of the challenge offline. An answer key can be found [here](./competitor/answers.md)

- [registry.xml](./competitor/registry.xml) -- the registry file provided to competitors
- [vault](./competitor/vault) -- the vault file provided to competitors

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download the [webroot directory](https://presidentscup.cisa.gov/files/pc5/individuala-round3-the-passed-of-us.zip). The zip contains the webroot directory for the secrets page and the backup file storage page. The zipped file is ~230 MBs and the extracted fileset is ~500 MBs.
- With the webroot files above you can recreate the websites, but you will also have direct access to the necessary files, namely the secrets.csv file and the required backup data file.




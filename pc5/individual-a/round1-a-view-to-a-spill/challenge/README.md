# A View to a Spill

_Challenge Artifacts_

Challenge Server Scripts and Required Files
- [setup.sh](./challengeserver/setup.sh) -- handles all of the artifact setup for the challenge and adds/moves the required files to the webserver and challenge.us site. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [GradingScript.sh](./challengeserver/GradingScript.sh) -- handles the grading for the challenge by checking for the correct token string on Kali and then checks all 10 IPv6 websites for the proper index.html and verify_login.php usage. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [change-names.sh](./challengeserver/chaneg-names.sh) -- alters the default video file names as they appear on the various websites by taking a random line value from video-names.txt and replacing the starting values. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [video-names.txt](./challengeserver/video-names.txt) -- provides a list of 100 date/timestamps to serve as video file names for the web pages, used by the change-names.sh script.

_Competitor Artifacts_

In lieu of accessing the challenge's virtual environment, you may use the artifacts listed below to conduct the major tasks of the challenge offline. The webserver directory is included as an additional large file download. An answer key can be found [here](./competitor/answers.md).

- [Aurellian-to-English-Alphabet.txt](./competitor/Aurellian-to-English-Alphabet.txt) -- an Aurellian to English translation document.
- [device-list.txt](./competitor/device-list.txt) -- a list a devices.
- [exemplar.pcpang](./competitor/exemplar.pcapng) -- exemplar pcap traffic file.
- [remediation.txt](./ccompetitor/remediation.txt) -- the remediation instructions provided once the competitor has passed the first part of the grading check.
- [transmission-log.txt](./competitor/transmission-log.txt) -- a list of transmissions.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download the [webroot directory](https://presidentscup.cisa.gov/files/pc5/individuala-round1-a-view-to-a-spill.zip). This package provides the webserver files in lieu of access to the webserver itself. Unnecessary video files were removed to reduce the overall size of the archive. The zipped file is ~300 MBs and the extracted file set is ~330 MBs.


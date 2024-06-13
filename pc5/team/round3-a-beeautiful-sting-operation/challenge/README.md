# A Bee-autiful Sting Operation

_Challenge Artifacts_

Challenge Server Scripts and Required Files


- [startTraffic.sh](./challengeserver/startTraffic.sh) -- This small script generates the SSH and Mail traffic related to "today's traffic" at the start of the challenge. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
- [breach-init.txt](./challengeserver/p1/breach-init.txt) -- Serves as the initial template for the breach report for part 1 of the challenge.
- [password.txt](./challengeserver/p1/passwords.txt) -- Supplies the passwords to add to the breach report at startup.
- [scp-scripts](./challengeserver/p2/scp-scripts/) -- Serve as the traffic generation scripts for "today's SSH login attempts in part 2 of the challenge. The startup script selects one of these to use at startup. Each script relates "today's" traffic to past traffic in a unique manner, creating 5 analysis paths while leveraging the same historical dataset. These may not operate as intended unless run with a VM configuration that mirrors what is in the hosted challenge.
- [TAM.csv](./challengeserver/p2/TAM.csv) -- Serves as the initial template for the threat actor matrix for part 2 of the challenge.
- [swaks-scripts](./challengeserver/p3/swaks-scripts/) -- Serve as the traffic generation scripts for "today's" mail logs in part 3 of the challenge. The startup script selects one of these to use at startup. Each script relates "today's" traffic to past traffic in a unique manner, creating 5 analysis paths while leveraging the same historical dataset. These may not operate as intended unless run with a VM configuration that mirrors what is in the hosted challenge.
- [phishing-report.txt](./challengeserver/p3/phishing-report.txt) -- Serves as the initial template for the phishing report for part 3 of the challenge.
- [scan-reports](./challengeserver/p4/scan-reports/) -- The scan reports for part 4 of the challenge. Each scan report relates to past traffic in a unique manner, creating 5 analysis paths while leveraging the same historical dataset. 

_Competitor Artifacts_

In lieu of accessing the challenge's virtual environment, you may use the artifacts listed below to conduct the major tasks of the challenge offline. Due to not having access to the Kibana dashboards or the Tpot system, the relevant data has been provided as .csv, log, or zip files. When following along with the solution guide, you may need to make small adjustments to the solution process. An answer key can be found [here](./competitor/answers.md)

Part 1
- [p1-breach-report.pdf](./competitor/p1/p1-breach-report.pdf) -- the breach report for part 1 of the challenge, as per the challenge guide
- [p1-shadow](./competitor/p1/p1-shadow) -- the shadow file for part 1 of the challenge, as per the challenge guide
- [p1-cowrie-passwords.csv](./competitor/p1/p1-cowrie-passwords.csv) -- an offline file for analyzing the list of Cowrie dashboard passwords 
- [p1-dionaea-passwords.csv](./competitor/p1/p1-dionaea-passwords.csv) -- an offline file for analyzing the list of Dionaea dashboard passwords 

Part 2
- [p2-threat-actor-matrix.csv](./competitor/p2/p2-threat-actor-matrix.csv) -- the threat actor matrix for part 2 of the challenge, as per the challenge guide
- [p2-download-logs.csv](./competitor/p2/p2-download-logs.csv) -- the download logs for part 3 of the challenge, as per the challenge guide
- [p2-ssh-attempts.png](./competitor/p2/p2-ssh-attempts.png) -- a screenshot showing "today's" ssh attempts
- [p2-downloads.png](./competitor/p2/p2-downloads.png) -- a screenshot showing the Cowrie downloads for the target traffic
- [p2-downloads.zip](./competitor/p2/p2-downloads.zip) -- the file set of downloaded files for offline analysis (these files are mostly innocuous, but take care to only view their text format or review them in a safe environment)

Part 3
- [p3-phishing-report.pdf](./competitor/p3/p3-phishing-report.pdf) -- the phishing report for part 3 of the challenge, as per the challenge guide
- [p3-messages.png](./competitor/p3/p3-messages.png) -- a screenshot showing "today's" mail logs
- [p3-mail-ip-list.csv](./competitor/p3/p3-mail-ip-list.csv) -- the full list of ip addresses that sent mail messages to the mail relay
- [p3-mail.log](./competitor/p3/p3-mail.log) -- the Mailoney dashboard mail message log
- [p3-attachments.zip](./competitor/p3/p3-attachments.zip) -- a collection of the physical attachments sent in the carious mail messages

Part 4
- [p4-scan-report.pdf](./competitor/p4/p4-scan-report.pdf) -- the scan report for part 4 of the challenge, as per the challenge guide
- [p4-alert-ids-by-count.csv](./competitor/p4/p4-alert-ids-by-count.csv) -- a list of all alerts for the target country (Germany) and their count, allowing you to corroborate with the solution guide details and scan report

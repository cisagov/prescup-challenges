# Lite 'Em Up

_Challenge Artifacts_

- [litecoin.zip](./challengeserver/litecoin.zip) -- Contains the blockchain, wallets, etc. Unzip this and place in /home/user/.litecoin directory.
- [litecoind.service](./challengeserver/litecoind.service) -- Systemd service to startup litecoind.
- [loader.service](./challengeserver/loader.service) -- Systemd service to run loader.sh.
- [loader.sh](./challengeserver/loader.sh) -- Bash script to load all wallets.
- [names.txt](./challengeserver/names.txt) -- Text file with all user names required for other scripts to loop through.
- [sender.py](./challengeserver/sender.py) -- Python script that randomizes the nucleus (also known as lone wolf) user, groups users into groups of three, and generates all of the transactions.
- [sender.service](./challengeserver/sender.service) -- Systemd service to run sender.py.

_Competitor Artifacts_

In lieu of the virtual challenge environment, you can solve the challenge with the file provided below. An answer key can be found [here](./competitor/answers.md)

- [regtest.zip](./competitor/regtest.zip) -- the regtest.zip package provided by challenge.us per the challenge guide. The package was generated on **May 8th, 2024** at roughly **2:30 PM EDT**. Therefore, you should look for transactions between ~2:30 PM EDT on May 7th and ~3:00 PM EDT on May 8th of 2024 to be safe.

Note that you will need litecoin-cli installed in order to process the files. You can install litecoind on Kali with the following command:

```
apt install litecoind
```





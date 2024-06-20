# Lite 'Em Up

*Solution Guide*

## Overview

*Lite 'Em Up* requires the competitors to analyze a Litecoin blockchain with ~200 blocks of  transactions across 25 users and their wallets. Each user has one wallet address.

## Preparing to answer the questions

This solution guide has various scripts and commands pre-built for you. The difficulty of this challenge lies in analyzing blockchain information and identifying the need for these scripts and commands. If you just copy and paste the commands, the challenge appears to be much easier to solve than it would to somebody without the solution guide.

On the **Kali** machine, browse to `challenge.us/files` and download `regtest.zip`.

Using the commands below: make a `.litecoin` directory, place the `regtest.zip` data into the `.litecoin` directory, and unzip it. 

```bash
mkdir /home/user/.litecoin
cp /home/user/Downloads/regtest.zip /home/user/.litecoin/
cd /home/user/.litecoin
unzip regtest.zip
```

Verify you see a `regtest` directory. Change directory into it:

```bash
ls
cd regtest
```

Within this directory, you should see a directory for blocks, wallets, and more. Verify you have the blockchain and 25 wallets within their respective directories. 

```bash
ls
cd blocks
ls #(ensure you see blk00000.data (the blockchain))
cd ../wallets
ls #(ensure you see 25 directories of wallets)
cd /home/user/.litecoin
```

To interact with this data, we're going to need `litecoind` and `litecoin-cli`. Run the command below to attempt to execute this command.

```bash
litecoind -regtest
```

Kali does not have these tools installed by default; you'll have to install them. When prompted to `litecoind`, enter `y` or run the command below.

```bash
sudo apt install litecoind
```

Now that we have the data in the default expected directory (`/home/user/.litecoin/regtest`), we can start `litecoind` and interact with the blockchain. Leave this window open and running after executing the command.

```bash
litecoind -regtest
```

In a new terminal tab, ensure you can interact with the blockchain:

```bash
litecoin-cli -regtest getblockcount
```

You should see 209 blocks. If you do not see 209 blocks identified within your blockchain, make sure your previous commands are correct, `litecoind` is still running in the previous tab, and look for any helpful logs within the previous screen regarding potential errors.

## Questions 1 and 2

*Regarding the person of interest, how many LTCs did this person SEND during their first sent transaction?*

*Regarding the person of interest, how many LTCs did this person RECEIVE during their first received transaction? *

To view the available commands we can execute, see the litecoin-cli help page: 

```bash
litecoin-cli -regtest help
```

To interact with the blockchain, let's view more information about it:

```bash
litecoin-cli -regtest getblockchaininfo
```

Here we see some basic information regarding the blockchain we are working with. Let's get the hash of the first block of the blockchain with the following command.

```bash
litecoin-cli -regtest getblockhash 0
```

The output of this command is the hash of the first block. For example, if the hash of your first block was: `530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9`; then run the following command to dive deeper into this block.

```bash
litecoin-cli -regtest getblock 530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9
```

Within this output, we see transactions (`tx`) that have occurred within this block and the hash of the next block (e.g., `91b4a0e9bc121adf09ff28c3e21e8398ec17f110d8c751b2efeda5c23dfae804`).

Verify the `nextblockhash` value matches the result of the following command.

```bash
litecoin-cli -regtest getblockhash 1
```

The best way to interact with the blockchain is to load all 25 wallets. For example, we could load Alice's wallet using the following command.

```bash
litecoin-cli -regtest loadwallet /home/user/.litecoin/regtest/wallets/alice_wallet
```

The following one-liner can be used to load all remaining wallets.

```bash
for i in /home/user/.litecoin/regtest/wallets/*; do litecoin-cli -regtest loadwallet $i; done
```

Now, we should be able to interact with the transactions within the blockchain. Let's look at Alice's transactions.

```bash
litecoin-cli -regtest -rpcwallet=/home/user/.litecoin/regtest/wallets/alice_wallet listtransactions
```

Copy the last `txid` value and place it in the following command to view more details about one of Alice's transactions. The example below uses the `txid`: `b59edbd85224ec4408d892779ada90408e5b66cff962b2c2a36551693a0240db`; however, you should change this to your correct `txid`.

```bash
litecoin-cli -regtest -rpcwallet=/home/user/.litecoin/regtest/wallets/alice_wallet gettransaction b59edbd85224ec4408d892779ada90408e5b66cff962b2c2a36551693a0240db
```

We are now seeing some wallet addresses (e.g., `rltc1qyle2fxn6wsmquef6md8tnuwnwdrevmwfsrpnlk`). We need to correlate each wallet address to a person. Run the following command to create a list of all users and their wallet addresses.

```bash
for i in $(ls /home/user/.litecoin/regtest/wallets | cut -d '_' -f1); do echo $i; done > ~/names.txt
```

Change directory to your home directory, install `jq`, and create the following file called `address-grabber.sh`.

```bash
cd ~
sudo apt install jq
vim address-grabber.sh
```

The contents of `address-grabber.sh` should be this:

```bash
while IFS= read -r line; do
    wallet_address=$(litecoin-cli -rpcwallet="/home/user/.litecoin/regtest/wallets/${line}_wallet" listtransactions | jq -r '.[] | select(.category == "receive") | .address' | uniq)
        echo "$line:$wallet_address" >> ~/namesandwallets.txt
done < ~/names.txt
```

Run the command below and verify `namesandwallets.txt` has been written out to.

```bash
bash address-grabber.sh
cat ~/namesandwallets.txt
```

Let's create a script that will loop through each name and check to see the names of the recipients of their transactions. Create the file `sent-to.bash` and enter the following lines:

```bash
while IFS= read -r name; do
while IFS= read -r wallet_address; do
	    matched_name=$(grep -F "$wallet_address" ~/namesandwallets.txt | cut -d ':' -f 1)
	        echo "$matched_name:$wallet_address" >> ~/${name}-sends-to.txt
	done < <(litecoin-cli -regtest -rpcwallet="/home/user/.litecoin/regtest/wallets/${name}_wallet" listtransactions | jq -r '.[] | select(.category == "send") | .address' | sort | uniq)
done < ~/names.txt
```

Run the script.

```bash
bash sent-to.bash
```

Open `alice-sends-to.txt` or any other recently created `*name*-sends-to.txt` file. You should see a pattern where most people send LTC to two people. Only one user sends to people from different social groups. For example, in the [screenshots](./img/), Alice, Nora, and Jade only send to each other. Bob, Charlie, and Ulysses only send to each other. Daisy, Max, and Wendy only send to each other. Ethan sends to Tina, Rachel, and Victor. This is one extra. Tina only sends to Ethan and Victor. Victor only sends to Tina and Ethan. This indicates the social group is Ethan, Victor, and Tina. Rachel sends to Fiona, Xavier, Daisy, Hannah, and Ethan! Each of these users that Rachel sends to are of unique social circles (Daisy (only sends/receives to/from Max and Wendy), Ethan (only sends/receives to/from Tina and Victor), Fiona only sends (only sends/receives to/from Ivan and Oscar), Hannah only sends (only sends/receives to/from Sam and Penelope), Xavier only sends (only sends/receives to/from George and Quentin), and Yara only sends/receives to/from Kevin and Lily). See [screenshots](./img/) to better visualize this data and social construct.

Please see this [visualization](./img/social-group-visualization.png) showing who sends/receives and that Rachel is the only user to send/receive from multiple social groups. All other users send/receive only to their social group.

Let's say Rachel is the only person that crosses multiple social circles. We need to find her transactions. Run the command below (replace the user with your nucleus/user of interest):

```bash
litecoin-cli -regtest -rpcwallet=/home/user/.litecoin/regtest/wallets/rachel_wallet listwallettransactions | jq 'sort_by(.timereceived)' | less
```

The first few transactions are not applicable as those were not within the last 24 hours. You should see:

- a `SendToAddress` - this the answer to Question 1, and 
- a `RecvWithAddress` - this is the answer to Question 2

If your answers are not correct, you may not have chosen the earliest one based on timestamp.

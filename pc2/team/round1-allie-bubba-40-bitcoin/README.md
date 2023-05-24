# Allie, Bubba, and the 40 Bad Bitcoin

Given a Bitcoin blockchain sample and the ID of a known-bad transaction,
players must identify whether a set of transactions occurring at a future time
are descendants of, or otherwise related to, the known-bad transaction.

**NICE Work Roles:**  
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)  
- [Threat/Warning Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0103](https://niccs.cisa.gov/workforce-development/nice-framework) - Examine recovered data for information of relevance to the issue at hand  
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework) for recovery of potentially relevant information  
- [T0783](https://niccs.cisa.gov/workforce-development/nice-framework) - Provide current intelligence support to critical internal/external stakeholders as appropriate  
- [T0786](https://niccs.cisa.gov/workforce-development/nice-framework) - Provide information and assessments for the purposes of informing leadership and customers; developing and refining objectives; supporting operation planning and execution; and assessing the effects of operations  

## Background

Allie, Bubba, Chuck, and DeeDee have all sent approximately 40 BTC to
Koinbase, an exchange service that happens to be subject to the type
of "Know your customers" legislation that requires it to refer suspect
activity to law enforcement for further review.

Our four customers all want Koinbase to exchange their Bitcoin for USD.

Following a subpoena issued as part of a US Government investigation,
Koinbase has provided details of the transactions they placed on the
public blockchain on behalf of these four customers.
Your job is to determine which, if any, of the four customers' Bitcoin
may be connected to known illegal activity, and to flag suspicious
transactions for further review by various law enforcement organizations.

## Setting Up

To solve this challenge, you need to begin by installing the
[Bitcoin software](https://bitcoin.org/en/download). Any of the supported
OS options should work, but these instructions have only been tested on
Linux and Windows.

***Caution***: When downloading the software, you may wish to avoid allowing
the software to start and automatically begin downloading the main, production
Bitcoin blockchain! At the time of this writing, that may potentially take
many hours, and utilize over 250GB of disk space, and is not needed to solve
this challenge.

## Getting Started

The required files are provided in the [challenge directory](challenge/). The provided files include
`data.md` (containing the public bitcoin addresses of Allie, Bubba,
Chuck, DeeDee, and Koinbase, as well as the transaction ID of the known
illegal ransomware payoff), a `regtest` folder containing the blockchain,
and a `btc_shell_alias` file containing a handy shortcut for easier
invocation of the `bitcoin-cli` command:

```
source btc_shell_alias
```

The challenge blockchain is meant to be used in `regtest` mode, as the real,
public (production) blockchain utilizes over 250GB of disk space.

Start `bitcoind` in a way that will not have it reach out to the network:

```
bitcoind -daemon -regtest -noconnect -reindex -txindex
```

Ensure that `bitcoind` is listening for ***local*** IPv4 client connections:

```
netstat -antp
...
tcp   0   0   127.0.0.1:18443   0.0.0.0:*   LISTEN   <some-pid>/bitcoind
...
```

Run

```
btcli -help [command]
```

for the list of available commands, and for details on any particular
command (hint: you may find `getchaintips`, `getblock`, `getrawtransaction`,
and `decoderawtransaction` of particular interest).

## For credit, answer the following questions:

1. (5%) Block ID (hash) of the active blockchain tip
2. (5%) Public address of the ransomware attacker
3. (60%) Transaction IDs (hashes) representing each user's deposit to
   Koinbase (15% for each TxID)
4. (30%) Each user's Koinbase deposit can be in one of the following
   situations:
    - a) coins part of ransomware payoff, received directly or indirectly
         from attacker
    - b) coins not part of ransomware payoff, but received from attacker
         (directly or through one or more intermediaries)
    - c) coins unrelated to either ransomware payoff or the attacker
   Identify the transaction ID that provides the funds (input) being turned
   over to Koinbase by a user who is *innocent* (i.e., to whom case "c", as
   described above, applies).

## Answer Guidelines

Answers should be either 64-character hex strings representing Bitcoin block and transaction IDs, or 35-character alphanumeric strings representing Bitcoin user public addresses.

Example:

| Q  | A                                                                  |
|----|--------------------------------------------------------------------|
| 1  | `49347fa63adc43f4ffb43ac7caa91d19cfe52093e61cae7450b769eb2844c6bb` |
| 2  | `2XBvVZb6LiGwUnN1ZtDUzhXV1Qh2kWNesUK`                              |
| 3A | `44bcb15c20a472dda166a688568d2ec2037e86ee6e5424ec0a82f5e3618744aa` |
| 3B | `973cfda05f4b85301e50f58dc16fcdbf6a9fcd3de25776c83adad61820573662` |
| 3C | `9bf6957ae31530164e14896995ed01f40a673597b8c609ec547f3edc549a55d8` |
| 3D | `7b914d13e74920da576ab9e7e0f66fed99be0757495c6e9d5d40896a638864bd` |
| 4  | `53cbd26b20a472dda166a688568d2ec2037e86ee6e5424ec0a82f5e3618834db` |

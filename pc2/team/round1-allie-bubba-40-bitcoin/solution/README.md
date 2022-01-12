# Allie, Bubba, and the 40 Bad Bitcoin

## 1. Setting Up


**NOTE**: Without lack of generality, we will use Linux to illustrate the
solution to this challenge.


You are provided a `regtest` folder containing the blockchain sample, and a
`data.md` file with the public Bitcoin addresses of Allie, Bubba, Chuck,
DeeDee, and Koinbase, as well as the transaction ID hash of the "bad"
(ransom payment) transaction.


As explained in the instructions, the challenge blockchain is expected to
be utilized generated in `regtest` mode. Therefore, the `bitcoind` daemon
should be started accordingly:

```
bitcoind -daemon -regtest -noconnect -reindex -txindex
```

Similarly, be sure to use the `-regtest` option when invoking `bitcoin-cli`.
A handy shortcut may be to create a shell alias:

```
alias btcli='bitcoin-cli -regtest'
```

## 2. Solving the Challenge

### 2.1. Finding the block ID of the active blockchain tip

Run `btcli getchaintips`, which will return the following:

```
$ btcli getchaintips

[
  {
    "height": 136,
    "hash": "47448ed59ecb35e5eec31bb6caa91d19cfe52093e61cae7450b769eb1751d5cc",
    "branchlen": 0,
    "status": "active"
  }
]
```

While sometimes there may be several competing blockchain tip *candidates*,
there's typically a winner with the highest `height` value, marked `active`.
In our case, that is:

```
47448ed59ecb35e5eec31bb6caa91d19cfe52093e61cae7450b769eb1751d5cc
```

### 2.2. Public address of ransomware attacker

We were provided with the transaction ID (or hash) of the "bad" (ransomware)
transaction. There is a `bitcoin-cli` subcommand, `getrawtransaction`, which
can be used to grab the contents of a transaction knowing its ID or hash:

```
$ btcli getrawtransaction 8d6e482252f84eaeeada387efb9ce56563ffc5bc42e4ec9d9119cfd4a6964611

0200000000010351488189e4b92994d9e7d4bf9dca0d30bac01b8d1c7db55b806363f2cebc5630000000001716001459231101960736bca7506ed7c3109af0e258d593feffffffb82c033a2dd98055e392d98c96831ebb0bd4f90961a64e2ca62011b26198bdc50100000017160014d8876e5448ac0a4c3d7d0ec58faf1d75c7cad81cfeffffffaa838df17606a1772e66c0a07249e218952cce765016276c10c1c7d30c0802f90100000017160014d8876e5448ac0a4c3d7d0ec58faf1d75c7cad81cfeffffff016c8623fc0600000017a914c1b7be2bfe010b41e72262c56e391a6bf089ad7b870247304402200e8c437bfcac430e912be0dbfd7b41da45a2e6e5c4efd0bb523414a586922a190220548c64a3cbe57848e594b90d08244f351172281a10213e77133c18802d73c96d0121023cda91af9383410dec3fb360c1d24588adc2d497ca6116691223147ff7f6b82c02473044022022fc2cd894dc5bd51d66a6704cc24505c03b9726babc9535ad9193d591b5d33202200532698d9dcb7fe189b31a5108fc16f4f58f81cf0ddbe7fc154b14cf255931af0121033dd72409a5663d56e11988786b2fe14acc0d81c015a01254f61037cea7d07ab2024730440220367b9fd413b7a098003c5acafd6b81c1460905970cc1b4ad5358d5816558919402204d2ea74e5a4d3fd764aadda95ef5640f2e3fbece2d6ff1b6b16129808229bcb60121033dd72409a5663d56e11988786b2fe14acc0d81c015a01254f61037cea7d07ab284000000
```

To obtain human-readable values, we use another subcommand of `bitcoin-cli`, named `decoderawtransaction`:

```
$ btcli decoderawtransaction $(btcli getrawtransaction 8d6e482252f84eaeeada387efb9ce56563ffc5bc42e4ec9d9119cfd4a6964611)

{
  "txid": "8d6e482252f84eaeeada387efb9ce56563ffc5bc42e4ec9d9119cfd4a6964611",
  "hash": "f158a329dc9d20ac7bc6fbfcfcf39cd6894ee602e465122e16181c8b2501c927",
  "version": 2,
  "size": 557,
  "vsize": 315,
  "weight": 1259,
  "locktime": 132,
  "vin": [
    {
      "txid": "3056bccef26363805bb57d1c8d1bc0ba300dca9dbfd4e7d99429b9e489814851",
      "vout": 0,
      "scriptSig": {
        "asm": "001459231101960736bca7506ed7c3109af0e258d593",
        "hex": "16001459231101960736bca7506ed7c3109af0e258d593"
      },
      "txinwitness": [

"304402200e8c437bfcac430e912be0dbfd7b41da45a2e6e5c4efd0bb523414a586922a190220548c64a3cbe57848e594b90d08244f351172281a10213e77133c18802d73c96d01",
        "023cda91af9383410dec3fb360c1d24588adc2d497ca6116691223147ff7f6b82c"
      ],
      "sequence": 4294967294
    },
    {
      "txid": "c5bd9861b21120a62c4ea66109f9d40bbb1e83968cd992e35580d92d3a032cb8",
      "vout": 1,
      "scriptSig": {
        "asm": "0014d8876e5448ac0a4c3d7d0ec58faf1d75c7cad81c",
        "hex": "160014d8876e5448ac0a4c3d7d0ec58faf1d75c7cad81c"
      },
      "txinwitness": [

"3044022022fc2cd894dc5bd51d66a6704cc24505c03b9726babc9535ad9193d591b5d33202200532698d9dcb7fe189b31a5108fc16f4f58f81cf0ddbe7fc154b14cf255931af01",
        "033dd72409a5663d56e11988786b2fe14acc0d81c015a01254f61037cea7d07ab2"
      ],
      "sequence": 4294967294
    },
    {
      "txid": "f902080cd3c7c1106c27165076ce2c9518e24972a0c0662e77a10676f18d83aa",
      "vout": 1,
      "scriptSig": {
        "asm": "0014d8876e5448ac0a4c3d7d0ec58faf1d75c7cad81c",
        "hex": "160014d8876e5448ac0a4c3d7d0ec58faf1d75c7cad81c"
      },
      "txinwitness": [

"30440220367b9fd413b7a098003c5acafd6b81c1460905970cc1b4ad5358d5816558919402204d2ea74e5a4d3fd764aadda95ef5640f2e3fbece2d6ff1b6b16129808229bcb601",
        "033dd72409a5663d56e11988786b2fe14acc0d81c015a01254f61037cea7d07ab2"
      ],
      "sequence": 4294967294
    }
  ],
  "vout": [
    {
      "value": 299.99990380,
      "n": 0,
      "scriptPubKey": {
        "asm": "OP_HASH160 c1b7be2bfe010b41e72262c56e391a6bf089ad7b OP_EQUAL",
        "hex": "a914c1b7be2bfe010b41e72262c56e391a6bf089ad7b87",
        "reqSigs": 1,
        "type": "scripthash",
        "addresses": [
          "2NAuWWz5LiGwUnN1ZtDUzhXV1Qh2kWMdrTJ"
        ]
      }
    }
  ]
}
```

The entire ransom amount is made out to the Bitcoin user public address
`2NAuWWz5LiGwUnN1ZtDUzhXV1Qh2kWMdrTJ`, which is (one of) the known addresses
used by the attacker.

### 2.3. Transaction IDs representing the four users' deposits to Koinbase

First, let's examine the active tip block (using `btcli getblock`):

``` 
$ btcli getblock 47448ed59ecb35e5eec31bb6caa91d19cfe52093e61cae7450b769eb1751d5cc

{
  "hash": "47448ed59ecb35e5eec31bb6caa91d19cfe52093e61cae7450b769eb1751d5cc",
  "confirmations": 1,
  "strippedsize": 640,
  "size": 1112,
  "weight": 3032,
  "height": 136,
  "version": 536870912,
  "versionHex": "20000000",
  "merkleroot": "77980bf90ece7a05ba395c3b33d4a858781aaf7cb2abdb9064af0082ed765fa1",
  "tx": [
    "1927f2087bc9149302668168fcfb702de15070aa69d38d2a5527a49cf33f45ef",
    "860faea05f4b85301e50f58dc16fcdbf6a9fcd3de25776c83adad61820464664",
    "9b803d13e74920da576ab9e7e0f66fed99be0757495c6e9d5d40896a638982af",
    "9bf6957ae31530164e14896995ed01f40a673597b8c609ec547f3edc549a55d8",
    "33aaa15c20a472dda166a688568d2ec2037e86ee6e5424ec0a82f5e3618733dd"
  ],
  "time": 1587144521,
  "mediantime": 1587142815,
  "nonce": 2,
  "bits": "207fffff",
  "difficulty": 4.656542373906925e-10,
  "chainwork": "0000000000000000000000000000000000000000000000000000000000000112",
  "nTx": 5,
  "previousblockhash": "2bc72ccc3d53d86119fb0cc2aa37103512300d4978b5957bb45171d66b79ebf0"
}
```

There are five transactions included in this block, one of which is a
so-called `coinbase` transaction, used by the miner to collect fees and
claim the per-block mining reward. Could we be this lucky, and have the
other four transactions be Allie, Bubba, Chuck, and DeeDee's Koinbase
deposits?

Before we proceed, let's create another shell alias (actually, a shell
*function* in this case), to simplify retrieval of transaction details
in human-readable form:

```
gettx () {
  local TXID=${1}
  btcli decoderawtransaction $(btcli getrawtransaction ${TXID})
}
```

Now, let's check one of the listed transactions:

```
$ gettx 9bf6957ae31530164e14896995ed01f40a673597b8c609ec547f3edc549a55d8

{
  "txid": "9bf6957ae31530164e14896995ed01f40a673597b8c609ec547f3edc549a55d8",
  "hash": "ec41f5628a351d9760dd1302969e7cb743f4e69afdbaec21738ce7168b511a35",
  "version": 2,
  "size": 215,
  "vsize": 134,
  "weight": 533,
  "locktime": 135,
  "vin": [
    {
      "txid": "6c6dc7321d66fdf11cb7ba3e459962204b658219b3833dfcafa9944b0c4321b6",
      "vout": 0,
      "scriptSig": {
        "asm": "0014f5c031dcb4da8019891ee391e94a246e9e7ed643",
        "hex": "160014f5c031dcb4da8019891ee391e94a246e9e7ed643"
      },
      "txinwitness": [

"3044022024fcd3140c4ef11e4456979cb3b39989b9c584539d8f3b795873a971ca8190a002201cffbea40a18a4766737d783d62b26872da7c0a485b1b05e137a4915220d7d1c01",
        "02f7b498e8aef77e2b5edefd763a3d694e38b2c34c34aecca948e27be1d89680c4"
      ],
      "sequence": 4294967294
    }
  ],
  "vout": [
    {
      "value": 39.99994000,
      "n": 0,
      "scriptPubKey": {
        "asm": "OP_HASH160 f335bee173174207323354a24a2c50ad0672a8fd OP_EQUAL",
        "hex": "a914f335bee173174207323354a24a2c50ad0672a8fd87",
        "reqSigs": 1,
        "type": "scripthash",
        "addresses": [
          "2NFRCaDA6LLd9gqKbygmD1HRj992T6KwM4k"
        ]
      }
    }
  ]
}
```

And, indeed, this transaction's output is sent to Bitcoin public user address
`2NFRCaDA6LLd9gqKbygmD1HRj992T6KwM4k`, which represents Koinbase. How do
we figure out who originated this transaction? We note that the list of
inputs consists of a single transaction ID:

```
6c6dc7321d66fdf11cb7ba3e459962204b658219b3833dfcafa9944b0c4321b6
```

whose first (0'th) output is being spent. We need to examine *that*
transaction in more detail, and find out who the recipient of its 0'th
output is:

```
$ gettx 6c6dc7321d66fdf11cb7ba3e459962204b658219b3833dfcafa9944b0c4321b6

{
  "txid": "6c6dc7321d66fdf11cb7ba3e459962204b658219b3833dfcafa9944b0c4321b6",
  "hash": "1a07c307552be294f8434aa8d026385dd173d67b13696302215b4ebe94380b97",
  "version": 2,
  "size": 247,
  "vsize": 166,
  "weight": 661,
  "locktime": 134,
  "vin": [
    {
      "txid": "a09569110cbdc7dc39630e3b7933c34ed54e0bc450ed830bcb07abcb7f31cd16",
      "vout": 1,
      "scriptSig": {
        "asm": "0014434ec9aa323bc99ed164cc64218cc24cb596cfc9",
        "hex": "160014434ec9aa323bc99ed164cc64218cc24cb596cfc9"
      },
      "txinwitness": [

"304402204561daa34f3aa11a314c7ba6b23c2843fc904699097f2b1a6901de8432e885b602202acfb869aedc59b2887622596e63a0d2a89841bca92dab718a2c237abe5285ca01",
        "03def707b558e4fea0fbb75fc71df45954d9386002dc541422a8df7fd90de4a84f"
      ],
      "sequence": 4294967294
    }
  ],
  "vout": [
    {
      "value": 39.99996680,
      "n": 0,
      "scriptPubKey": {
        "asm": "OP_HASH160 a7c3d3239f29dd12188531a5df94682041790502 OP_EQUAL",
        "hex": "a914a7c3d3239f29dd12188531a5df9468204179050287",
        "reqSigs": 1,
        "type": "scripthash",
        "addresses": [
          "2N8YHRTnbu4Jv3unDGFbfDNXn8QCeihbf4A"
        ]
      }
    },
    {
      "value": 159.99987060,
      "n": 1,
      "scriptPubKey": {
        "asm": "OP_HASH160 58dd6daaf06b48831e30eba00a10488a9d7a0bfb OP_EQUAL",
        "hex": "a91458dd6daaf06b48831e30eba00a10488a9d7a0bfb87",
        "reqSigs": 1,
        "type": "scripthash",
        "addresses": [
          "2N1M6iH9frtAqkrrJTjJurwscADQf1zxb1t"
        ]
      }
    }
  ]
}
```

The first (0'th) output goes to `2N8YHRTnbu4Jv3unDGFbfDNXn8QCeihbf4A`, which
is Chuck's public Bitcoin address. So, therefore, transaction

```
9bf6957ae31530164e14896995ed01f40a673597b8c609ec547f3edc549a55d8
```

in the active tip block represents Chuck's deposit. We can follow a similar
process to find out who issued the other transactions in that block:

| User   | Transaction ID                                                     |
|:-------|:-------------------------------------------------------------------|
| Allie  | `33aaa15c20a472dda166a688568d2ec2037e86ee6e5424ec0a82f5e3618733dd` |
| Bubba  | `860faea05f4b85301e50f58dc16fcdbf6a9fcd3de25776c83adad61820464664` |
| Chuck  | `9bf6957ae31530164e14896995ed01f40a673597b8c609ec547f3edc549a55d8` |
| DeeDee | `9b803d13e74920da576ab9e7e0f66fed99be0757495c6e9d5d40896a638982af` |

### 2.4. Does a Koinbase deposit's transaction ancestry look "suspicious"?

Since we used Chuck to illustrate the earlier answer, we'll use his
Koinbase deposit once again to find out if there's anything untoward
in his transaction's ancestry. We know from earlier that Chuck was paid
via transaction:

```
6c6dc7321d66fdf11cb7ba3e459962204b658219b3833dfcafa9944b0c4321b6
```

whose input was provided by the 0'th output of transaction:

```
a09569110cbdc7dc39630e3b7933c34ed54e0bc450ed830bcb07abcb7f31cd16
```

Examining *that* transaction in turn:

```
$ gettx a09569110cbdc7dc39630e3b7933c34ed54e0bc450ed830bcb07abcb7f31cd16

{
  "txid": "a09569110cbdc7dc39630e3b7933c34ed54e0bc450ed830bcb07abcb7f31cd16",
  "hash": "aecf385bd75af0ecba565447d9135401da6f02fe3fd27b478e1d7b7228d4db83",
  "version": 2,
  "size": 247,
  "vsize": 166,
  "weight": 661,
  "locktime": 133,
  "vin": [
    {
      "txid": "8d6e482252f84eaeeada387efb9ce56563ffc5bc42e4ec9d9119cfd4a6964611",
      "vout": 0,
      "scriptSig": {
        "asm": "0014d1e81e4b9db27c31c5814521511ab34bdee96eb4",
        "hex": "160014d1e81e4b9db27c31c5814521511ab34bdee96eb4"
      },
      "txinwitness": [

"304402201828988bf640d2831a699ff84dd9343e986966239328bf1da0ab3b11b1702bf0022066da9f538185f684071e74f0d943d84e6c9753450d047e01d0b5ed951f829e9801",
        "023d0638a003e5ad1ef279a7e0e0e31520a84ca346e2fe0cd07482e2ea0f3f138c"
      ],
      "sequence": 4294967294
    }
  ],
  "vout": [
    {
      "value": 100.00000000,
      "n": 0,
      "scriptPubKey": {
        "asm": "OP_HASH160 44575ce05cae6e601ce6fa208927e0ccbe0aff37 OP_EQUAL",
        "hex": "a91444575ce05cae6e601ce6fa208927e0ccbe0aff3787",
        "reqSigs": 1,
        "type": "scripthash",
        "addresses": [
          "2MyUabQGqSyfznj4LHYmuk8jBx8bSCBzf13"
        ]
      }
    },
    {
      "value": 199.99987060,
      "n": 1,
      "scriptPubKey": {
        "asm": "OP_HASH160 4e4a91efef330db066eb8d8256e83b4350e96fe7 OP_EQUAL",
        "hex": "a9144e4a91efef330db066eb8d8256e83b4350e96fe787",
        "reqSigs": 1,
        "type": "scripthash",
        "addresses": [
          "2MzPC2TyLESbBWtXKXpghxTu2gyvo7qztnY"
        ]
      }
    }
  ]
}
```

shows that the input is the "evil" ransomware transaction itself:

```
8d6e482252f84eaeeada387efb9ce56563ffc5bc42e4ec9d9119cfd4a6964611
```

This would indicate that Chuck's coins were part of the ransomware payoff,
and were received by Chuck indirectly, through an intermediary.

We follow a similar process to determine whether all other users' coins
are related in any way to the known ransomware transaction, or even just
to the ransomware attacker (`2NAuWWz5LiGwUnN1ZtDUzhXV1Qh2kWMdrTJ`), without
actually having been part of a *known* evil transaction:

| User   | Status                                                            |
|:-------|:------------------------------------------------------------------|
| Allie  | c) coins unrelated to either ransomware payoff or the attacker    |
| Bubba  | b) coins unrelated to ransomware payoff, received from bad actor  |
| Chuck  | a) ransomware proceeds, received through intermediary             |
| DeeDee | a) ransomware proceeds, received through intermediary             |

The identity of the "innocent" customer is `Allie`, and the answer to Q#4
(the transaction ID that pays Allie the amount she turns over to Koinbase)
is:

```
b7d36e30562f459230a7f2ab34cf1c2231d5b9d8e54a3d5ae1ccfad50d6c67d5
```

# Answer Key

| Q  | A                                                                  |
|:---|:-------------------------------------------------------------------|
| 1  | `47448ed59ecb35e5eec31bb6caa91d19cfe52093e61cae7450b769eb1751d5cc` |
| 2  | `2NAuWWz5LiGwUnN1ZtDUzhXV1Qh2kWMdrTJ`                              |
| 3A | `33aaa15c20a472dda166a688568d2ec2037e86ee6e5424ec0a82f5e3618733dd` |
| 3B | `860faea05f4b85301e50f58dc16fcdbf6a9fcd3de25776c83adad61820464664` |
| 3C | `9bf6957ae31530164e14896995ed01f40a673597b8c609ec547f3edc549a55d8` |
| 3D | `9b803d13e74920da576ab9e7e0f66fed99be0757495c6e9d5d40896a638982af` |
| 4  | `b7d36e30562f459230a7f2ab34cf1c2231d5b9d8e54a3d5ae1ccfad50d6c67d5` <br> (Allie)|

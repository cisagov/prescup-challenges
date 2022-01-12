<img src="../../../pc1-logo.png" height="250px">


# 13

## Solution

### Message 0
This one should be fairly simple. Eyeballing the contents carefully will lead
to the observation that this is simply backwards (reversed) ASCII, and the full
message reads:

- "index of first letter in the name of the smallest addressable unit of memory
in most architectures"

We're looking for  the word "Byte", and "B" is the second letter of the
alphabet, so our first clue is `2`.

### Message 1
There's a hint in `challenge/notes.txt` in the form of a key:

```
LgCqSwV-aldTQzgqrF3ndMe4qG30KtTj-hUZ_PblzMI=
```

This is a Fernet symmetric key which, when used on the encrypted message, will
yield our next message:

```
k = Fernet(b'LgCqSwV-aldTQzgqrF3ndMe4qG30KtTj-hUZ_PblzMI=') # from notes.txt
with open("challenge/1/1", "r") as f:
    s = f.readlines()[0]
s = k.decrypt(s.encode())
print(str(s))
```

The clue is:

- "index of second or fourth letter in name of oss application to view and
save kerberos tickets"

The answer is "mImIkatz", and our next clue is therefore `9`.

### Message 2
There is a key file next to the message. How about we try each of the 12 keys,
maybe one of them works? The message ends up being:

- "first letter of name of famous german encryption machine in ww2 used to
transmit coded messages"

The answer is, obviously, "Enigma". However, we're still looking for a number
(remember, the key is a GPS lat-long coordinate). So, as for the earlier clues,
let's go with the alphabetic index of the letter E, which is `5`.

### Message 3
Looks the same as before, except now we have 10,000 different keys!!!
The Fernet `decrypt()` method throws an exception if the key doesn't match,
so we have all we need to write a loop, and have the computer try all keys
in rapid sequence, printing out the result when `decrypt()` succeeds:

- "index of first letter of digial artifact installed on server to authenticate
identity of website and encrypt traffic"

The word is "Certificate", so our clue is `3`.

### Message 4
With a bit of additional eyeballing, the astute competitor may notice that this
message has characters shifted by one: "joefy" stands for "index", with each
letter replaced by the immediately following one in the alphabet. This is known
as "ROT" or "Caesar" cypher, in this case with offset 1:

- "index number of the first letter first word in name of infamous russian
hacker group _ bear"

The message is talking about the "Fancy bear" hacker group, and so our clue is
the number `6`.

### Message 5
Could this be another Caesar cypher, with a different offset? As it turns out,
Yes! The offset here is `2`, so "first" becomes "hktuv", and so on:

- "first letter of current united states cyber command commander last name"

The name is "Nakasone", and since this time we need a letter, we go with `N`.

### Message 6
How many possible Caesar cyphers are there? Maybe we could just try them all
in a loop, and see if anything makes sense? As it turns out, this one's offset
is `10`, and the message is:

- "index of _/O"

We guess that it's the letter "I" we're after, and its index is `9`.

### Message 7
More of the same. Turns out this one's offset is `13`, a.k.a. the (in)famous
"rot-13" encryption:

- "index of first letter unix command to modify access permissions to file
system objects"

The word we're looking for is "Chmod", so our clue is `3`.

### Message 8
This is another "rot-13":

- "index of first letter unexpected event in program that disrupts the normal
flow of instructions"

The word is "Exception", so the clue will be `5`.

### Message 9
Another "rot-13":

- "index of first letter name of current head of cia"

The name's "Gina", and the clue is therefore `7`.

### Message 10
This one should look familiar -- it is a `base64` encoded string, standing for:

- "index of first letter of missing word ross ulbrict, the _ pirate roberts"

The word is "Dread", so the clue will be `4`.

### Message 11
Using the remaining clues from `challenge/notes.txt`, we suspect this might be
encrypted using an [Affine cipher](https://en.wikipedia.org/wiki/Affine_cipher):

```
class Affine(object):
   DIE = 128
   KEY = (7, 3, 55)

   def __init__(self):
      pass

   def encryptChar(self, char):
      K1, K2, kI = self.KEY
      return chr((K1 * ord(char) + K2) % self.DIE)

   def encrypt(self, string):
      return "".join(map(self.encryptChar, string))

   def decryptChar(self, char):
      K1, K2, KI = self.KEY
      return chr(KI * (ord(char) - K2) % self.DIE)

   def decrypt(self, string):
      return "".join(map(self.decryptChar, string))

a = Affine()
with open("challenge/11/11", "r") as f:
    s = f.readlines()[0].strip()
    s = a.decrypt(s)
print(s)
```

The decrypted message is:

- "the same index as two and eight"

Messages 2 and 8 both resulted in the clue being `5`, so that's what we use
here as well.

### Message 12
The last message is another Affine-encrypted string, yielding:

"the first letter of four letter application that retreives files over http
https ftp and ftps"

The answer is "Wget", and since we're looking for a letter, not a number, we
use `W`.

### Solution
The flag we seek will therefore be `29°53′6″N 93°57′45″W`. For a fully
automated solver (written in Python) please see the enclosed script, `s.py`.

<br><br>

Flag - `29°53′6″N 93°57′45″W`


## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.

# Solution

This challenge relies on participant performing curiosity driven research - the key order for Vigenere cipher is based off of the chronological order of the Tyrants of Miletus found on en.wikipedia.org/wiki/Aristagoras. The ciphertext (which is 59 characters long and results in 59! possible permutations).

A quick overview of the data in question shows a bunch of directories and files of random data. There is however, a supplied solution.py file which was started by the previous player, and this offers three hints.

1. Use python3
2. We'll be using the Vigenere cipher
3. The key and flag is in the format KEY: PCUPCTF

Looking at the image files, there is one directory where the contained images look computer generated, as opposed to any other normal picture directory.

Also, a quick search of installed python packages will show stegonographic tools already installed on the machine.

## Hints

1. "Mr. Bellaso" in the description is a direct pointer to the orginal author of the Vigenere cipher - [Giovan Battista Bellaso](https://en.wikipedia.org/wiki/Giovan_Battista_Bellaso)

2. The key.py file as mentioned above

3. [Aristagoras](https://en.wikipedia.org/wiki/Aristagoras) led the Ionian revolt against the Persian empire in 499 BC. He timed the revolt with other greek city states via an early example of steganography: A compatriot sent a message by shaving a slaves head, tattooing the message, waiting for the hair to grow back and then sending the slave to deliver the message. When he made it to Miletus, he re-shaved his head and successfully delivered the message. Shave, get it?

4. Associated with Aristagoras above are the tyrants of Miletus, which is a folder in the challenge, with all the tyrant's names appearing as files.

## Expected Player Response:

1. Players download zip file for challenge

2. Unzip to a mess of different files — text, documents, images
Grepping text will return several false flags

3. Players should look at images. Several various directories of "hacker" images. Odd "miletus" directory, and contains a file key.py, which gives a hint at solution. Also contains a number of similar simple dark images with random text written on them, these files have stego values embedded within them

4. Image stenography will return random bits of Vigenère cipher data

5. Player will need to use python to automate stenography evaluation of images (there will be many)

6. Player will need to assemble text, decrypt and piece together flag. Note that files are not placed in a straightforward order

7. The title of this challenge, the folder name and the names of the files therein should lead players to https://en.wikipedia.org/wiki/Aristagoras - and the chronological listing of the names:

keys = ["Amphitres", "Thrasybulus", "Thoas", "Damasanor", "Histiaeus", "Aristagoras", "Timarchus"]

e.g. 0-Thoas.png is really 0-3.png in ordering

8. Players will need to decipher the contained string IJYKKZJCGLTEBUWGLETHGPDFNUATJNXWCOJQGYCPTRTFNWGUJANUHQVNEJYG using Vigenère

# Generator

The code in the `generate/` directory shows how the challenge was initially built.

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.

<img src="../../pc1-logo.png" height="250px">

# Fun With Crypto

## Background
We found a pair of executables with names suggesting that they are used to encrypt and decrypt files. Both executables
appear to be command line tools. The decryption tool seems to expect a path to a file, an encryption key, and an
initialization vector. The encryption tool seems to expect a path to a file, suggesting that the encryption key and
initialization vector are hard-coded.

In addition to these two tools, we also found a file that appears to be encrypted and we believe that it was encrypted
with the same tool that we found.

## Getting Started

In the challenge folder, there are three files: **encrypt**, **decrypt**, **flag.txt.ct**.

You will need to decrypt **flag.txt.ct** with the encryption key and initialization vector found in the **encrypt**
tool. The **decrypt** tool is provided for convenience and will provide little or no information that you would not also
find in the **encrypt** tool.

Once you have the key and initialization vector, the **decrypt** tool can be used to decrypt the flag.

For example:

If you were to copy the encrypted flag file to the Desktop, and you determined that the key was the array of bytes
`00 01 ab cd` and the initialization vector was the array of bytes `02 ef`, then you could invoke the program as
follows:

`decrypt.exe "C:\Users\Student\Desktop\flag.txt.ct" "00 01 ab cd" "02 ef"`

This would print the decrypted contents to your Command Prompt.

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.

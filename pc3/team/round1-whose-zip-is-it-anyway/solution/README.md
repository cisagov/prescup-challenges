# Whose ZIP is it anyway? Solution

Analyze, decode, and convert the state of the challenge files to extract the information within them. 

Please reference the `solution.py` script accompanying this solution guide for examples of how to solve this challenge. 

## Analyzing the File's Contents

To begin, look at the contents of the files; each one has been encoded with its own type. Try to determine which encoding was used and then the best method of decoding it. 

Considering the challenge README said the files had been converted AND encoded is a hint that the files need to be converted back to hexadecimal before they can be converted back to their original state. When analyzing the files, try to determine what encoding was used to convert the hex code.

## Converting Files Back to Their Original Hex Form

Attached in the `solution.py` script is an example of how the code can be converted back to its original hex form. This is one example available to convert the files back to hex.

## Determining the Encoding of Each File

#### File0

Notice that the file only contains a single string of numbers. This should hint that the encoding used might be a base. Upon further inspection, the numbers used range from 0 to 9; this should be another hint that its encoding can't be octal or binary. Considering what's in the file and that the code should be converted back to hex, decimal should be one of the first conversion methods to consider. 

#### File1

This file contains various amounts of characters with a `\u` format before each one. This should be a giveaway that the file's original hex code has been converted to Unicode. 

#### File2

This file contains various amounts of characters with `0b` appearing in between each value. With this, only '`1`'s and '`0`'s are in this file. This indicates that the hex code was converted to binary.

#### File3

You'll see that it will contain various amounts of characters, and it may appear a bit more confusing as nothing quite stands out. But if you look you'll see that the string `0o` is appearing in between values. With this, the only digits in this file range from `0 to 7`. This should indicate that the hex code was converted to octal.

#### File4

This one will likely be the most difficult as nothing quite stands out. Looking at the file's contents will show that it does have letters, numbers, and some special characters; this eliminates any encoding that specializes in one of those. Also notice that only a select few special characters appear within the file, so that should be a strong hint that `Base64` is the encoding present in the file. 

## Finding the File's Type (File Signature/Magic Number)

Once the files have been converted back to their original hex format, analyze the bytes to determine the type of the file. This can be done by analyzing the first 2-16 bytes of the hex code. This will give the `file signature` or `magic number`. In the `solution.py` script is an example line of code that will put out those first handful of bytes. These bytes then just need to be cross referenced by any site or database that has known magic numbers recorded. 

## Converting the Files

Once file types have been determined, convert the hex code back to each one's original file format. This can be done by using the following bash command: 
```bash
xxd -plain -revert <fileContainingHex> <reverted_file Extension>
```

## Extracting Passphrase Information 

Depending on the file type, there are different ways of extracting each part of the passphrase. Below is the list of possible file types and how to extract each one's information:

1. `png`: The image will be of a `number`.
2. `pdf`: The file will have a `number` written on the document itself.
3. `deb`: You can extract the files in the package using the command and once extracted, will contain a `number`:
```
dpkg-deb --extract /path/to/file.deb
```
4. `iso`: mount the ISO and once done, it will have a file containing a `number`.
5. `gzip`: Unzip the file with gzip and it will have a file containing a `number`.
6. `bzip2`: Unzip the file with bzip2 and it will have a file containing a `number`.
7. `pcap`: Open the pcap in wireshark and there is only one transfer that was captured. Extract the data from the packets and this will give a `number`.

## Determining the Meaning Behind the Numbers and Using the Periodic Table Cipher

The last part requires some deduction. There are five numbers, ranging from 1-102. Look at the zip file's name `AtomicElements`. This is a hint at the cipher that must be used to convert each number into its part of the secret passphrase.
There are multiple online resources for this, or it can be done manually (for example: 1=H, 2=He, 3=Li, etc). There will be five different elements once they have been converted, and the order that they go in is based on which file they were found in. 
If it were just the file names, it would look like so: <file0+file1+file2+file3+file4>. 

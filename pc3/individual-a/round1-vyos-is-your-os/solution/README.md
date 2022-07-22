# VyOS is your OS Solution

## 1. **VYOS Config**
    On the VYOS router checking the firewall reveals a rule that does not belong.
<img src="./img/t15_image_0.PNG">

    Viewing the commit history allows us to identify when the hostile changes were made.
<img src="./img/t15_image_1.PNG">

    The task to patch the firewall to its pre-breach state is as easy as reversing the diff results in `/config/config.boot`
<img src="./img/t15_image_2.PNG">
<img src="./img/t15_image_3.PNG">

## 2. **Trace Compromise**
    Finding the source of the hostile firewall rule is less straightforward, but can be done by examining the authorization log.
<img src="./img/t15_image_4.PNG">

    The only IP address that was approved to make edits on VYOS is the Win10 admin address, which is us. However, there are more connections than our activity accounts for.
    The next step is to examine our machine for compromise
<img src="./img/t15_image_5.PNG">

    And the known hostile IP has 2 connections on our machine. To find the source of those `netstat -anob` works but TCPView works better:
<img src="./img/t15_image_6.PNG">
<img src="./img/t15_image_7.PNG">

    And the next step is to simply kill those processes, and delete their respective executables
<img src="./img/t15_image_8.PNG">

## 3. **Malware Server**
    Finding the source of the malware takes us back to VYOS, this time examining firewall logs
<img src="./img/t15_image_9.PNG">
<img src="./img/t15_image_10.PNG">

    This will reveal traffic both from the known hostile IP address, and a second address on the 10.5.5.0/24 subnet. 
    Examining the socket will reveal it is a web server
<img src="./img/t15_image_11.PNG">

    And a second copy of one of the two malware payloads can be downloaded from the link on the website. We've found the malware server.

## Submission

    The challenge has three submission tokens.

    Token 1 is the IP address of the web server the adversary uses to host malware
    Token 2 is obtained from `challenge.us` after fixing the firewall
    Token 3 is obtained from `challenge.us` after removing persistence from the Windows admin machine

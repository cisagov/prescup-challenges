# Digital Vigilante Solution

## Get web server credentials

Start up wireshark in your current subnet and start sniffing traffic. You'll see that there is a conversation occurring via Hpings between a user on an external host and someone inside the network. The external host will be requesting the web servers credentials as it was apparently talked about previously between the two people. The web server will then send the credentials but they wont send it as normal plaintext. 

You'll see that the file is being transferred via the FTP traffic coming from the internal IP. You'll see that they are connecting to an external host using the credentials `anonymous` and  `guest`. 
This FTP traffic will contain the credentials but in a different format then expected. The user at the web server will take a screenshot of the credentials, convert the png into plain hexcode, and then put it in a file using the following command:

```
xxd -plain WSCreds.png > picHex.txt
```

In order to get the credentials you will need to export the file containing the hex code from the packet and put it into a file. This can be done in wireshark, right click on the packets `data` section, then you can export the packet bytes to any file and location. From here you will need to reverse the hexcode to make it the image again, you can use the command:

```
xxd -plain -revert picPlainFormat.txt pic.png
```

The image will contain the credentials for the internal web server

## Run a Man-in-The-Middle attack

You will need to then run a man in the middle attack and spoof the firewall and the external host receiving the FTP transfer. 
You can do this by using the arpspoof command.
You can achieve a successful attack by running the command:

```
sudo arpspoof -i eth0 -r -t 130.44.210.150 130.44.210.8
```

This is all thats needed to insert yourself between the two machines.

## write + execute scapy script to get files on web server

You will then need to write a scapy script which is a python library that has the ability to create packets pretending to be another machine. Scapy has the ability to craft an HTTP three way hand shake and GET request. You must forge the IP as the one that is currently in communication with the internal machine and run the request so you can bypass the firewall. Check the script.py file attached to see an example of a working script. 

internal web server ip is: `172.16.20.156`

You also need to disable the RST packets from being sent from your own machine so that the handshake can be completed. The commands for that are:

```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 130.44.210.150 -j DROP
```
```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 130.44.210.99 -j DROP
```

Scapy needs to be ran with higher priv, so when you go to execute it run it like so: `sudo python script.py`

You will then be able to get the layout of the web server via multiple requests and be able to start pulling files. The solution script will get the PDF file for you, but you will need to change the path to get the second file hosted on the server.

## Get information from files

You will then need to retrieve the two files that are being hosted on the web server. Once done you will see that the file `PA.pdf` file has been encrypted with an unknown cipher. The second file is `hc.zip`, and this will contain the cipher used to encrypt the file. The problem is is that in order for the cipher to work it requires a key that it bases its shift around. The key can be found in the pdf's metadata under the `Keywords` section. The string is 9 characters long as thats whats needed for the cipher. The key is `dhcidbjek`

## Decrypt the file

All thats left to do is decrypt the encrypted document word by word running it through the `hc.py` program. Once done, you can read the document and realize that the name of the project is `Adolla` and the owners name is `Beni Licht`.

Key locations:
 - "Keywords" metadata in PA.pdf

V1:
    Project Name: Adolla
    Project Owner: Beni Licht 

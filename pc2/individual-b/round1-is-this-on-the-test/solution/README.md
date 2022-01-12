# Is this on the test? Solution



This challenge involves analyzing the current topology via packet captures and other means to determine how to gain access to one of the machines thats inside their network. The information needed to successfully pass this challenge is the correct IP to configure your machine with, the hostname of the vulnerable machine you will gain access too, the port you used to access it and the final flag that is located on that machine.

## Correct configuration of IP

Log in and you will see that there is a folder on the desktop that is labeled **subnets**. Open the four pcaps in that folder and you will see various traffic.

Once you analyze it you will find that there is one IP address not being used in each subnet, those IPs are: 192.168.58.40 for variant 1, 192.168.132.79 for variant 2, 192.168.176.118 for variant 3, and 192.168.210.165 for variant 4. But to know which IP will be correct, you must assign each IP to your machine and begin to sniff the network and see if there is anything going on that 

would provide you with any information. The correct IP to configure will be based on the variant, variant 1 being 192.168.58.40, variant 2 being 192.168.132.79, and 

so on with 3 and 4. You will know which one is correct when you begin to sniff the network and see some traffic going on between two hosts as only one of the four 

networks will have that occurring in each version

## Hostname

Once you see the traffic, you will need to analyze it. You will see a conversation happening between hosts via hpings, in there they will mention which host they are 

looking to gain access too. the hostnames are as follows: variant 1 is Ron, variant 2 is Champ, variant 3 is Brick, and variant 4 is Brian. 

## Port

To determine the port you will need to do a nmap scan of all the machines in that network, once done you will see that only one host from that subnet should have one 

port open. They are as follows: variant 1 is 22, variant 2 is 21, variant 3 is 80, variant 4 is 443. This will be be the method of access. 

## Flag

To get this flag you must combine the information found previously. In the conversation that occurs over the network, a zip file is being sent. You can export it from the pcap however you wish. The method i used was:

 - Export the bits containing the login information within wireshark, do this by left click > export packet bytes > save as `"hostname".zip`

 - Change the permissions of this new file to allow you to look into it

 - Inside there will be a file with the login credentials

The information to log in for each variant is as follows: variant 1 is ssh with creds leader::

Achn0r!1000, variant 2 is ftp with creds sport:Wh@@mmy1, variant 3 is http with creds weatherman::Zer01Q00, variant 4 is https with creds field::SP@nth3r66. 

Once  logged in to each machine, the flag will be easy to find as it is in a text file named **flag**. 

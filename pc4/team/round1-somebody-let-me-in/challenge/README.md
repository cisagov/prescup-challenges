# Somebody Let Me In

_Challenge Artifacts_

The offline version of this challenge assumes you are running all client and server processes on the same local virtual system and can sniff traffic locally. Therefore, the arpspoofing methods described in the solution guide can be performed, but are no longer required.

In order to execute the challenge offline with the minimum footprint, a Linux-based system with Python installed, preferably Kali, is required. You can leverage the use of virtual network adapters to send all client traffic within the VM locally with only one network adapter device.

While these instructions follow the minimal route of using a single virtual system, those more comfortable with virtualization may also run the challenge in a three-system setup where one acts as the client/FOB system, the second acts as the server/receiver system, and the third acts as the man in the middle system. 

All client, server, and setup scripts can be found in the [challenge directory](.), which includes the following:

- [Client Scripts](./client)
  - [network.sh](./client/network.sh) - the client network setup script
  -	[client1.sh](./client/client1.sh) - the first client/FOB traffic script
  -	[client2.sh](./client/client2.sh) - the second client/FOB traffic script
- [Server Scripts](./server)
  - [network.sh](./server/network.sh) - the server network setup script
  -	[server1.py](./server/server1.py) - the first server/door code receiver
  -	[server2.py](./server/server2.py) - the second server/door code receiver
  - [server3.py](./server/server3.py) - the third server/door code receiver

1. Run both networking scripts first, adjusting for your system's interface names and/or network configuration commands if not using a Kali virtual system.

2. Start all three server processes:
```bash
python3 server1.py &
python3 server2.py &
python3 server3.py &
```

3. Execute the client scripts to initiate FOB to receiver traffic. You may run each client script one at a time or both at the same time. Note that the third receiver does not require a client/FOB traffic script.

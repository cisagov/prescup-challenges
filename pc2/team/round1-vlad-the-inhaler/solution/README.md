# Vlad the Inhaler Solution


First, open your PCAP file in Wireshark:

```
wireshark inhaler.pcap
```

### 1. Determine the client and VPN pool addresses in play

1. This is perhaps easiest to accomplish by selecting
   `Statistics -> Conversations -> IPv4` from Wireshark's menu.
2. Make a list of the IPv4 addresses having "conversations" with the VPN
   server (`12.0.0.54`) -- that would be the list of VPN clients, one of
   which is the target of your investigation.
3. Make a list of the IPv4 addresses in the VPN pool range
   (`128.2.149.0/24`) -- each of them represents a VPN tunnel endpoint
   address assigned to one of the VPN clients.

### 2. Determine the VPN pool address used to download "Vlad the Inhaler"

1. Isolate packets representing `HTTP` requests (by entering `http` into
   Wireshark's "display filter" bar)
2. Carve out each distinct image: on each `HTTP GET` packet, use
   `RightClick -> Follow -> HTTP Stream`, then select just the server
   response, and save it to a file as `raw`; Once saved, edit the resulting
   file to remove the HTTP headers, including the two newlines preceding the
   actual binary payload.
3. View each image (e.g., with Firefox), to determine if it represents
   "Vlad the Inhaler".
4. Once found, make a note of the VPN pool address that requested the image
   download: that is the tunnel endpoint address allocated to our suspect.

### 3. Use traffic correlation to identify the suspect's client IPv4 address

On the assumption that traffic to/from the suspect VPN pool address is
strongly correlated with tunnel traffic between the client we seek to
identify and the VPN server, let's try to match graphic representations
(i.e., ***histograms***) of the traffic to/from the VPN pool address with
one client's tunnel traffic to/from the VPN server:

1. Select `Statistics -> I/O Graph` from the Wireshark menu.
2. De-select (or remove) the entries automatically chosen by Wireshark
   (by repeatedly clicking on the `-` button)
3. Add an entry for the suspect VPN pool address: Click on `+`, pick a
   `Graph Name` (e.g., "Pool Address"), set the display filter (e.g.,
   `ip.addr==128.2.149.100`), and, optionally, assign the graph a color
   that will help you more easily identify it down the road.
4. Enable the entry (by clicking on its `Enabled` checkbox), then pick an
   interval that lets you best see the "shape" of the traffic (e.g., 10ms
   or 100ms).
4. Add similar entries for each tunnel client IPv4 address, making sure the
   `Graph Name` is properly labeled for easy identification, and the color
   is distinguishable from other entries, particularly that of the entry
   representing the suspect VPN pool address.
5. For each client IPv4 address, enable its traffic histogram alongside the
   histogram representing traffic from the suspect VPN pool address;
   ***One*** particular client's histogram will be an almost perfect match!

### Answer

The responsible client IP address is `72.252.9.10`.

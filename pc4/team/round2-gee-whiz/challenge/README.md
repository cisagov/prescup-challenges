# Gee Whiz 

_Setup_

## Server Setup

1. Set up an ubuntu machine

2. Compile a binary, `/usr/sbin/pc4tc18.srv`, from the `pc4tc18.c` source file:

   ```bash
   gcc -o pc4tc18.srv pc4tc18.c -lcrypto -static -Wall
   ```

3. Run `/usr/sbin/pc4tc18.srv aaaabbbbccccddddaaaabbbbccccdddd`

## Firewall Setup

1. Set up an ubuntu machine with *two* network interfaces
   - one connected to the server (described above), for which it should act
     as the default gateway
   - another connected to the same network as the machine running the grading
     script

2. Assuming the server's IP address is `192.168.4.254`, and the server facing
   interface of our firewall machine is `192.168.4.1`, set up iptables rules
   (e.g., in `etc/local`) to also forward filtering decisions to userspace:

   ```bash
   # DNAT (forward 31337 to srv):
   iptables -t nat -A PREROUTING -p tcp -i ens32 --dport 31337 \
         -j DNAT --to-destination 192.168.4.254:31337

   # Enqueue traffic to srv for userspace filtering:
   # (NOTE: `--queue-bypass` implies `ACCEPT` in absence of userspace filter)
   iptables -A FORWARD -p tcp --dport 31337 \
         -j NFQUEUE --queue-num 0 --queue-bypass
   ```

## Artifacts

Competitors are given `drvctl.bin` (a RISC-V binary that, when reverse
engineered, provides information about the ordering of the x, y, z, and time
fields.

Competitors also receive a sample filter script `sample_filter.c`, which they
can modify and make applicable to network packets traversing the firewall box
(between the grading script and the network listener/server as configured
above).

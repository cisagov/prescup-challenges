# Trust Level: Plain Zero
_Challenge Artifacts_


- [sensoroni_securityonion_tlpz.pcap](./sensoroni_securityonion_tlpz.pcap) -- A packet capture taken from the hosted environment which captures the exfiltration activities. 
- [Files-TrustLevelPlainZero.zip](./Files-TrustLevelPlainZero.zip) -- A compressed directory which contains all possible files which may have been exfiltrated. 


Attacker Machine (used in the hosted environment)
- These artifacts are placed on the attacker machine and run when the challenge is deployed in the hosted environment to exfiltrate data. They will not operate as intended unless run in an environment which mirrors the hosted challenge. The hosted environment includes an installation of Pritunl v.1.0.2678.71. 
    - [attacker-clicker.service](./attacker/attacker-clicker.service): Ensures the `attacker-clicker.sh` scripts runs and restarts upon completion.
    - [attacker-clicker.sh](./attacker/attacker-clicker.sh): Logs in to the zero trust application, browses to and downloads four files. This script then points to `icmp-sender.py`, `dns-sender.py`, `ntp-sender.py`, and `udp-sender.py` to exfiltrate the data.
    - [icmp-sender.py](./attacker/icmp-sender.py): Exfiltrates the steel file over ICMP
    - [dns-sender.py](./attacker/dns-sender.py): Exfiltrates the account file over DNS
    - [ntp-sender.py](./attacker/ntp-sender.py): Exfiltrates the exchange file over NTP
    - [udp-sender.py](./attacker/udp-sender.py): Exfiltrates the fingerprint file over a broadcast address via UDP/12345

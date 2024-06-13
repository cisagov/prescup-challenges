#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sleep 75

fluff96_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f1`
fluff96_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f113`
fluff96_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f113`
fluff96_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f113`
fluff96_ip="$fluff96_octet1.$fluff96_octet2.$fluff96_octet3.$fluff96_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff96_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff96.txt

# Another Random Scan

fluff97_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f2`
fluff97_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f114`
fluff97_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f114`
fluff97_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f114`
fluff97_ip="$fluff97_octet1.$fluff97_octet2.$fluff97_octet3.$fluff97_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff97_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff97.txt

# Another Random Scan

fluff98_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f3`
fluff98_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f115`
fluff98_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f115`
fluff98_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f115`
fluff98_ip="$fluff98_octet1.$fluff98_octet2.$fluff98_octet3.$fluff98_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff98_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff98.txt

# Another Random Scan

fluff99_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f4`
fluff99_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f116`
fluff99_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f116`
fluff99_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f116`
fluff99_ip="$fluff99_octet1.$fluff99_octet2.$fluff99_octet3.$fluff99_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff99_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff99.txt

# Another Random Scan

fluff100_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f5`
fluff100_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f117`
fluff100_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f117`
fluff100_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f117`
fluff100_ip="$fluff100_octet1.$fluff100_octet2.$fluff100_octet3.$fluff100_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff100_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff100.txt

# Another Random Scan

fluff101_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f6`
fluff101_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f118`
fluff101_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f118`
fluff101_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f118`
fluff101_ip="$fluff101_octet1.$fluff101_octet2.$fluff101_octet3.$fluff101_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff101_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff101.txt

# Another Random Scan

fluff102_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f7`
fluff102_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f119`
fluff102_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f119`
fluff102_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f119`
fluff102_ip="$fluff102_octet1.$fluff102_octet2.$fluff102_octet3.$fluff102_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff102_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff102.txt

# Another Random Scan

fluff103_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f8`
fluff103_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f120`
fluff103_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f120`
fluff103_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f120`
fluff103_ip="$fluff103_octet1.$fluff103_octet2.$fluff103_octet3.$fluff103_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff103_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff103.txt

# Another Random Scan

fluff104_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f9`
fluff104_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f121`
fluff104_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f121`
fluff104_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f121`
fluff104_ip="$fluff104_octet1.$fluff104_octet2.$fluff104_octet3.$fluff104_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff104_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff104.txt

# Another Random Scan

fluff105_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f10`
fluff105_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f122`
fluff105_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f122`
fluff105_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f122`
fluff105_ip="$fluff105_octet1.$fluff105_octet2.$fluff105_octet3.$fluff105_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff105_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff105.txt

# Another Random Scan

fluff106_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f11`
fluff106_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f123`
fluff106_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f123`
fluff106_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f123`
fluff106_ip="$fluff106_octet1.$fluff106_octet2.$fluff106_octet3.$fluff106_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff106_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff106.txt

# Another Random Scan

fluff107_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f1`
fluff107_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f124`
fluff107_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f124`
fluff107_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f124`
fluff107_ip="$fluff107_octet1.$fluff107_octet2.$fluff107_octet3.$fluff107_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff107_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff107.txt

# Another Random Scan

fluff108_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f2`
fluff108_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f125`
fluff108_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f125`
fluff108_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f125`
fluff108_ip="$fluff108_octet1.$fluff108_octet2.$fluff108_octet3.$fluff108_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff108_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff108.txt

# Another Random Scan

fluff109_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f3`
fluff109_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f126`
fluff109_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f126`
fluff109_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f126`
fluff109_ip="$fluff109_octet1.$fluff109_octet2.$fluff109_octet3.$fluff109_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff109_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff109.txt

# Another Random Scan

fluff110_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f4`
fluff110_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f127`
fluff110_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f127`
fluff110_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f127`
fluff110_ip="$fluff110_octet1.$fluff110_octet2.$fluff110_octet3.$fluff110_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff110_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff110.txt

# Another Random Scan

fluff111_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f5`
fluff111_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f128`
fluff111_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f128`
fluff111_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f128`
fluff111_ip="$fluff111_octet1.$fluff111_octet2.$fluff111_octet3.$fluff111_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff111_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff111.txt

# Another Random Scan

fluff112_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f6`
fluff112_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f129`
fluff112_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f129`
fluff112_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f129`
fluff112_ip="$fluff112_octet1.$fluff112_octet2.$fluff112_octet3.$fluff112_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff112_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff112.txt

# Another Random Scan

fluff113_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f7`
fluff113_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f130`
fluff113_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f130`
fluff113_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f130`
fluff113_ip="$fluff113_octet1.$fluff113_octet2.$fluff113_octet3.$fluff113_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff113_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff113.txt

# Another Random Scan

fluff114_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f8`
fluff114_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f131`
fluff114_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f131`
fluff114_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f131`
fluff114_ip="$fluff114_octet1.$fluff114_octet2.$fluff114_octet3.$fluff114_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff114_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff114.txt

# Another Random Scan

fluff115_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f9`
fluff115_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f132`
fluff115_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f132`
fluff115_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f132`
fluff115_ip="$fluff115_octet1.$fluff115_octet2.$fluff115_octet3.$fluff115_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff115_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff115.txt

# Another Random Scan

fluff116_octet1=`vmtoolsd --cmd 'info-get guestinfo.o1' | cut -d ' ' -f10`
fluff116_octet2=`vmtoolsd --cmd 'info-get guestinfo.o2' | cut -d ' ' -f133`
fluff116_octet3=`vmtoolsd --cmd 'info-get guestinfo.o3' | cut -d ' ' -f133`
fluff116_octet4=`vmtoolsd --cmd 'info-get guestinfo.o4' | cut -d ' ' -f133`
fluff116_ip="$fluff116_octet1.$fluff116_octet2.$fluff116_octet3.$fluff116_octet4"

ip addr flush dev ens32
sleep 5
ip addr add $fluff116_ip/4 dev ens32

ip route add default via 240.0.0.1
subnets=("10.1.1.0/24" "10.2.2.0/24" "10.3.3.0/24" "10.4.4.0/24" "10.7.7.0/24")

selected_subnet=${subnets[$RANDOM % ${#subnets[@]}]}

top_ports=$((RANDOM % 1000 + 1))

echo "Selected subnet for scanning: $selected_subnet"
echo "Scanning top $top_ports ports"

nmap --top-ports $top_ports $selected_subnet -oN ~/scan-fluff116.txt

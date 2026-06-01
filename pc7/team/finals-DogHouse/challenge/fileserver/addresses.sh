#!/bin/bash
while true; do
    plc_ip=$(host -4 plc 2>/dev/null | awk '/has address/ {print $4; exit}')

    if [[ -n "$plc_ip" ]]; then
        echo "Resolved plc to $plc_ip"
        break
    fi
    sleep 1
done

ot_ip=$(ping -R -c1 plc | grep $(hostname) | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)

first_three=$(echo $ot_ip | cut -d '.' -f 1-3)
last_octet=$(echo $ot_ip | cut -d '.' -f 4)
if [ $last_octet -eq 255 ]; then
    range="250-255"
else
    for i in $(seq 5 5 255); do
        if [ $last_octet -lt $i ]; then
            num=$(( $i - 5 ))
            range=$num-$i
            break
        else continue
        fi
    done
fi
echo By next week: Need to put the new firmware updates on the fileserver so the PLC on the $first_three.$range network can pull them. > /home/fileuser/TODO.txt
sed -i "s/plc_ip/$plc_ip/g" /tmp/helper.py
sed -i "s/ot_ip/$ot_ip/g" /tmp/helper.py

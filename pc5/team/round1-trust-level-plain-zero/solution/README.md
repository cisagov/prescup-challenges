# Trust Level: Plain Zero

*Solution Guide*

## Overview

This challenge requires competitors to find four files exfiltrated from a zero trust environment. Challengers extract pcap traffic from Security Onion and examine it to find the four files sent via different means: icmp, dns, ntp, and udp.

Security Onion takes about eight minutes to be fully functional.

## Question 1

*Regarding the steel file that was exfiltrated, what are the last THREE digits of the original filename?*

1. On the Kali machine, navigate to `10.4.4.4` and log in to Security Onion.
2. Click **PCAP**, then click  ‘**+**’  to **Add Job**. 
   - **Sensor ID**: securityonion
   - **Filter Begin** and **Filter End**: cover the range of the time the challenge is deployed (e.g., **Filter Begin** 2023-05-08 12:00:00 and **Filter End** to 2023-05-08 13:00:00) 
3. Click **Add**.
4. When Status is **Completed**, click the **binoculars**, then the **download icon** to download the pcap.
5. Open the pcap with Wireshark. Sifting through the pcap, you will see `10.2.2.51` sending **four** ping packets to `45.79.150.150` at a very rapid rate between ping requests. The length of these pings is also different than a typical ping request. For some reason there is a lot  more data in these packets than typical ping requests. If you see more than four ping packets, it is because the insider keeps exfiltrating data again and again. We only need to examine the first four ping packets.
6. Examine the human-readable data within each of the four icmp packets from `10.2.2.51` to `45.79.150.150`. Notice it appears to be ingredients and a recipe. Right-click each of the four icmp packets, **Copy...as Printable Text**, and save it to a file (icmp.file). An example of the data is below.

```yaml
Ingredients:
- Titanium: 0.5g
- Tungsten: 2g
- Molybdenum: 5g
- Manganese: 25g
- Vanadium: 3g

Melting temperature: 1420 degrees Celsius
Cooling rate: 45 degrees Celsius per second
Final hardness: 84 HRC
```

7. Log into the Zero Trust internal sensitive web server at https://s7331.merch.codes/, navigate to the **Network** tab in **Web Developer Tools**, and open the first steel file. You should see a **200 GET** request in your developer tools. Copy it as a curl request and then use a script like the one below to download all "steel" files. Your curl request will be a different cookie. Make sure you update the curl to have the appropriate `$number` variable used throughout. Make sure you have the `-k` and `--output` set too.

```bash
#!/bin/bash

for ((i=1; i<=1000; i++))

do

number=$(printf "%04d" "$i")

curl -k https://s7331.merch.codes/steel/new-steel-prototype-$number.txt -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Referer: https://s7331.merch.codes/steel/' -H 'Connection: keep-alive' -H 'Cookie: pritunl-zero=MTY4MzQ4OTAxNHxabGlhN0VFQm50akJCMjFhWE5lN0dOdi1CU1c0b0VSYm91ZEU4Mm9yOGt5Z3pjSjF5cjQ0Q3FSRFBYRk9mU3FlS0wzbUpYQm1hdUlxbmxqeUVOaVhFdUhxVzNfLWIzSDd1NmhSR2F4UkF4ODNnVGI5M05GSDFOOWZ6dnh0eC0xMnk2OVpPRjNBQVBlY0xtTFVCRXhfekwyR1RnSHViem1IWGNQeTdEOUl0VWF6OHNUUm1mbHUxeVd0TWpraDh5UUV0N0hPN0w0cG9faGoyd2FHU2pWLThHTmtleW11dkpKRkVEUENFdEZaaWVUMU9HR1loVTl3MWY4azVMeTNrVHdyNVdfcW1KS0VZdVdHb0xtU25odHBDbUFnfKsOnyC3qiEGnQJZGknVm07DNjsgZzuYBMfYdRJt64_W' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-User: ?1' -H 'If-Modified-Since: Sat, 29 Apr 2023 02:35:02 GMT' -H 'If-None-Match: "c8-5fa706fc544d8-gzip"' --output steel-$number.txt.gz

gunzip steel-$number.txt.gz

done
```

You should now be able to hash the **icmp.file** with the command:

```bash
md5sum icmp.file
```
In this example, the hash was `5f894664b83897b4e21c4bd5f8d5f9fb`. To find the match, run the command:

```bash
md5sum steel-* | grep 5f894664b83897b4e21c4bd5f8d5f9fb
```
In this example, **steel-0562.txt** was the original steel file that was exfiltrated. The correct submission for Question 1 in this example is: `562`.

## Question 2

*Regarding the account file that was exfiltrated, what are the last THREE digits of the original filename?*

1. On the Kali machine, navigate to `10.4.4.4` and log in to Security Onion.
2. Click **PCAP**, then click  ‘**+**’  to **Add Job**. 
   - **Sensor ID**: securityonion
   - **Filter Begin** and **Filter End**: cover the range of the time the challenge is deployed (e.g., **Filter Begin** 2023-05-08 12:00:00 and **Filter End** to 2023-05-08 13:00:00)
3. Click **Add**.
4. When Status is **Completed**, click the **binoculars**, then the **download icon** to download the pcap.
5. Open the pcap with Wireshark. Diving into the **Statistics**, **Conversations**, we see `10.2.2.51` has sent a few packets to `45.79.150.151`.
6. Add **ip.addr == 45.79.150.151** to only see this traffic. We see four DNS queries to `45.79.150.151` and no responses. `45.79.150.151` is not a known or common public DNS server (e.g. `8.8.8.8`, `1.1.1.1`, etc.). If you see more than four, that is because the insider is continuously exfiltrating the traffic. Look at the first four packets in this solution guide. Each of these DNS queries is looking for a subdomain within `legit.site`:

```bash
TmFtZTogS0JWTFVHQU8gTktPSlJHTlNJ.legit.site
VkdECkFjY291bnQgTnVtYmVyOiAxMjgz.legit.site
MzE2ODg2NDQxOTY3MDYKVmFsdWU6ICQ0.legit.site
NTM5MDk5Cg==.legit.site
```

​	The first three queries are all the same length, while the final one is much shorter. These all appear to be base64. 

7. Merge all of your subdomains into one string. For example: 

`TmFtZTogS0JWTFVHQU8gTktPSlJHTlNJVkdECkFjY291bnQgTnVtYmVyOiAxMjgzMzE2ODg2NDQxOTY3MDYKVmFsdWU6ICQ0NTM5MDk5Cg==`

8. Decode your base64 string and output it to a file (dns.file) with the command:

```bash
echo -n TmFtZTogS0JWTFVHQU8gTktPSlJHTlNJVkdECkFjY291bnQgTnVtYmVyOiAxMjgzMzE2ODg2NDQxOTY3MDYKVmFsdWU6ICQ0NTM5MDk5Cg== | base64 -d > dns.file
```

9. Read the dns.file with the command: 

```bash
cat dns.file
```
​	It appears the file is an account file.

10. Log into the Zero Trust internal sensitive web server at https://s7331.merch.codes/. Navigate to the **Network** tab in **Web Developer Tools**, and open the first account file. You should see a **200 GET** request in your developer tools. Copy it as a curl request and then use a script like the one below to download all account files. Your curl request will be a different cookie. Make sure you updated the curl to have the appropriate `$number` variable used throughout. Make sure you have the `-k` and `--output `set as well.

```bash
#!/bin/bash

for ((i=1; i<=1000; i++))

do

number=$(printf "%04d" "$i")

curl -k https://s7331.merch.codes/accounts/account-number-$number.txt -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Referer: https://s7331.merch.codes/accounts/' -H 'Connection: keep-alive' -H 'Cookie: pritunl-zero=MTY4MzUxMjI0OHxXVzI4dWgzZlhUWWF0cldfU2w0WDl5NGkxeHU4NUxrbUg3OXFHMEFUVTVWOWpHa2FfczJPajdfS1hwdmZxMnpUZVBSSXRkcjZtdGhOTWRZVmZWalB3THlycUFxdlBNdVJUU3dtZzIyLUNYdnRtbHBlTWo1Z2NyQTBrbm4yS19pbjJBd05id1pVT0FoblcxUjNkcmlPMHhULTRTbzlndV94Q1ZpRXJOYUZ4ZWxZTGNqQTdWOGp2VVM4SzZBX1ZwUlpmMW83SjhIb2M4cmJwaDZUTUk3VXVXWlBSU2czaG40UllYY0dqTUlaRVFHX3Fna2Z5cXJqTTZDUkRoZ1h6eHZTWndRdHNOb3dDc2hGR1gzTHJfUkxteDF1fCtfC4t-4IGmcPzSk6uws9raa4CDz7AhXX48O74m1xCC' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-User: ?1' -H 'If-Modified-Since: Sat, 29 Apr 2023 03:23:38 GMT' -H 'If-None-Match: "4f-5fa711d98fff5-gzip"' --output account-$number.txt.gz

gunzip account-$number.txt.gz

done
```

11. You should now be able to hash the dns.file with the command:

```bash
md5sum dns.file
```

12. In this example, the hash was `9ac5dae3fa248404e92228daeeb5e59a`. To find the match, run the command:

```bash
md5sum account-* | grep 9ac5dae3fa248404e92228daeeb5e59a
```

In this example, **account-0392.txt** was the original account file that was exfiltrated. The correct submission for Question 2 in this example is: `392`.

## Question 3

*Regarding the exchange file that was exfiltrated, what are the last THREE digits of the original filename?*

1. On the Kali machine, navigate to `10.4.4.4` and log in to Security Onion.
2. Click **PCAP**, then click  ‘**+**’  to **Add Job**. 
   - **Sensor ID**: securityonion
   - **Filter Begin** and **Filter End**: cover the range of the time the challenge is deployed (e.g., **Filter Begin** 2023-05-08 12:00:00 and **Filter End** to 2023-05-08 13:00:00)
3. Click **Add**.
4. When Status is **Completed**, click the **binoculars**, then the **download icon** to download the pcap.
5. Open the pcap with Wireshark. Diving into **Statistics**, **Conversations**, we see `10.2.2.51` has sent a few packets to `45.79.150.152 `over NTP.
6. Add **ip.addr == 45.79.150.152** to only see this traffic. Examining the NTP timestamps within the packet in Wireshark highlights that the timestamps are incorrect as the timestamps appear to include dates in the decade of the 2060's.
7. Right-click any of the NTP packets and click **Follow**, **UDP Stream**. Save it as ASCII; save the file as ntp.file. Remove any non-hexadecimal characters or symbols and re-save the file as ntp.file with the command:

```bash
sed -i ‘s/\.//g’ ntp.file
```

In this example, we received the string of 

```
596f752068617665206265656e20696e766974656420746f206120736563726574206d656574757020696e204d6f756e7461696e76696c6c65210a0a546865206d6565747570206c6f636174696f6e2069732061742053616d75656c20426c61636b277320686f757365206f6e20417370656e204c616e65207374726565742e0a0a546f206765742074686572652c20666f6c6c6f7720746865736520646972656374696f6e733a0a0a5374617274206174204d6f756e7461696e76696c6c652c20417370656e204c616e652e20476f2065617374206f6e204269726368776f6f6420436f757274207374726565742e20476f206e6f727468206f6e204c696e636f6c6e20537472656574207374726565742e20476f2077657374206f6e204d61706c65776f6f64204472697665207374726565742e20476f206e6f727468206f6e20526976657273696465204472697665207374726565742e20476f20736f757468206f6e20526976657273696465204472697665207374726565742e200a546865206d65657475702073746172747320617420323032342d30332d32362031333a31373a30382e20446f6e2774206265206c617465210a
```

8. Place this string into **Security Onion / CyberChef** and run the "magic" recipe. The string converts from hexadecimal to human-readable. In this example the string says:

```
You have been invited to a secret meetup in Mountainville!

The meetup location is at Samuel Black's house on Aspen Lane street.

To get there, follow these directions:

Start at Mountainville, Aspen Lane. Go east on Birchwood Court street. Go north on Lincoln Street street. Go west on Maplewood Drive street. Go north on Riverside Drive street. Go south on Riverside Drive street. 
The meetup starts at 2024-03-26 13:17:08. Don't be late!
```

9. Log into the Zero Trust internal sensitive web server at https://s7331.merch.codes/, navigate to the **Network** tab in **Web Developer Tools**, and open the first exchange file. You should see a **200 GET** request in your developer tools. Copy it as a curl request and then use a script like the one below to download all "exchange" files. Your curl request will be a different cookie. Make sure you update the curl to have the appropriate `$number` variable used throughout. Make sure you have the `-k` and `--output` set too.


```bash
#!/bin/bash

for ((i=1; i<=1000; i++))

do

number=$(printf "%04d" "$i")


curl -k https://s7331.merch.codes/exchanges/meetup-location-$number.txt -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Connection: keep-alive' -H 'Referer: https://s7331.merch.codes/exchanges/' -H 'Cookie: pritunl-zero=MTY4MzUzNjg1N3x6b0xPNHZvQjFFNTVWeDJnMWVoWEFyWmNBSTNWdzd1ZXg5M2VaM3pEdm1uaGZsLXFlb0daM180MEtTTmk1LWxXbjduZ0YyQ2JlMUx4M1FEbkdhdXJLVzNsNTgtR2dFUjV0LXBySjlZajQ5RGJCMXFWX0JIVnVVdnVnUGYwQnRhMS1Va3RTZDhsYTFrMEtja1V4NnY3SEpYVHlaM2dtQmdmMTM5d0ROLTh5clRfZVI1VkdWVDk2UVR1MkxRMENnSjh2a3NDRnFMOHh0eG91NWlkY0NXcElpbFBNcU1oUmVJYnFnbEl4RnFqbWdURkVodXpXSDRxYlBIcWtZdmN4alFFMk53N29GSnVxZVZxR19kTlRrLVUwZTBafNmhcQX5SJHPo589gN2FiEaIJNo2wpHGzmHOWB_Z2Brr' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-User: ?1' --output exchange-$number.txt.gz

gunzip exchange-$number.txt.gz

done
```

10. Once you have all of the **exchange-*.txt** files, run the command below to find the original file; however, you must replace the timestamp with the timestamp found in your magic CyberChef decoding:

```bash
grep "2024-03-26 13:17:08" *.txt
```

In this example, **exchange-0551.txt** was the original account file that was exfiltrated. The correct submission for Question 3 in this example is: `551`.

## Question 4

*Regarding the fingerprint file that was exfiltrated, what are the last THREE digits of the original filename?*

1. On the Kali machine, navigate to `10.4.4.4` and log in to Security Onion.
2. Click **PCAP**, then click  ‘**+**’  to **Add Job**. 
   - **Sensor ID**: securityonion
   - **Filter Begin** and **Filter End**: cover the range of the time the challenge is deployed (e.g., **Filter Begin** 2023-05-08 12:00:00 and **Filter End** to 2023-05-08 13:00:00)
3. Click **Add**.
4. When Status is **Completed**, click the **binoculars**, then the **download icon** to download the pcap.
5. Open the pcap with Wireshark.
6. Click **Statistics**, **Endpoints**. Sorting by UDP ports, we see traffic is being sent to `255.255.255.255` over `12345`. Using open source resources, this port is not known for any legitimate broadcast traffic.
7. Add **ip.addr == 255.255.255.255** to see only this traffic.
8. Right-click any of the UDP packets and **Follow**, **UDP Stream**. Save it as **Raw**; save the file as 12345.file.
9. Run the command below to see the data is zlib compressed data:

```bash
file 12345.file
```

10. Run the command below to install zlib-flate:

```bash
sudo apt install qpdf
```

11. Run the command below to uncompress the file:

```bash
zlib-flate -uncompress <12345.file > uncompressed-12345.file
```

12. Run the command below and we see the resulting file is base64:

```bash
cat uncompressed-12345.file
```

13. Run the command below to decode the file:

```bash
base64 -d uncompressed-12345.file > decoded-12345.file
```

14. Run the command below to see the file is a PNG file:

```bash
file decoded-12345.file
```

15. Use FireFox to open this file to view it with the command:

```bash
firefox decoded-12345.file
```

Log into the Zero Trust internal sensitive web server at https://s7331.merch.codes/, navigate to the **Network** tab in **Web Developer Tools**, and open the first fingerprint file. You should see a **200 GET** request in your developer tools. Copy it as a curl request and then use a script like the one below to download all "fingerprint" files. Your curl request will be a different cookie. Make sure you update the curl to have the appropriate `$number` variable used throughout. Make sure you have the `-k` and `--output` set too.


```bash
#!/bin/bash

for ((i=1; i<=1000; i++))

do

number=$(printf "%04d" "$i")

curl -k https://s7331.merch.codes/fingerprints/fingerprint-$number.png -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Connection: keep-alive' -H 'Cookie: pritunl-zero=MTY4MzUzODc4MnxRekwydmNtQVRWU3dEclktMUdrb0VJQlBBenNoS2NMMUlibjZHX3RMYlV1Q3pNWU93R0xUamNGMmdlV2ZKSlJVQ0ZoX0R3WDU3RnZQZnVlVzNHT00yYmFIVW1oUlRYWmdkaTRIQjM2UXdDOHA0YzRLemNZUFhUcTZOSC0xN2M4ZUVtRWJmTkhBUWhiVTdFODNCU0pRcXEwa1pJODdibWtUTW9YaVFXdWs2ZDNYaE1XYm1FV1E4NXhCZHlnR2FjQXVHMVdHaF9lNlN5c05OeTRqeGRlYWNkS1ExZUp3cVQwMHJIcmFLREI0WTBnN0gtZGN0S2FSQUVsb25BVzFJcVlNWXdDRkN6RTZTZ0hCU25jMTdhNUcwWFg2fMxoQYXUTLwtL0rNaeXyrKTvBDD01TYFwwc5O_WAssfw' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: cross-site' -H 'Sec-Fetch-User: ?1' --output fingerprint-$number.png


done
```

16. You should now be able to hash the **decoded-12345.file** with the command:

```bash
md5sum decoded-12345.file
```

17. In this example, the hash was `96a7ff9c0dd928472773c8298499ef45`. To find the match, run the command:

```bash
md5sum fingerprint-* | grep 96a7ff9c0dd928472773c8298499ef45
```

In this example, **fingerprint-0790.txt** was the original steel file that was exfiltrated. The correct submission for Question 4 in this: `790`.

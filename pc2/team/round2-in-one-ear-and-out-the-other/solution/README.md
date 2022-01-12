# In One Ear and Out the Other Solution 

## Question 1: 

1. Using Volatility, run the following 
    ```
    vol.py -f <location of memdump> --profile=Win2012R2x64 netscan
    ```

2. Review list of connections and will reveal connection back to the initial C2 server at `94.72.252.234`

3. Open `packetcapture.cap` with Wireshark and go to `Statistics > Conversations`

4. Review conversations in the 94.72.x.x subnet. The answer is the IP address that is in the attacker subnet but is different than the C2 server. Filtering on this IP address and observing conversations will confirm that.

## Question 2: 

1. Using Wireshark, discover the first ICMP packet to be sent to the exfiltrated address 

2. The data field of the packet contains the name of the file
   - This can be accomplished by creating a filter on either the ICMP protocol or the attacker's data exfiltration address that was identified in the Volatility `netscan` results.


## Question 3:

1. Open the packet capture within Wireshark and locate the ICMP conversation 

2. In the conversation, the packets containing data can be observed of having a packet of a specific data length, however it does not match any of the prescribed answers

3. To obtain the actual data chunk size, you need to analyze several of the ICMP packet data fields. In each, the data in the data field is padded by a random number and "::", which will make up a certain number of bytes in each variation.


## Question 4:

1. Similar to Question 1, this can also be found using the command below and reviewing the same input:

    ```
    vol.py -f <location of memdump> --profile=Win2012R2x64 netscan
    ``` 

## Question 5:

1. Run 
    ```
    vol.py -f <location of memdump> --profile=Win2012R2x64 netscan
    ```

2. Output the file to a directory so the connection from `10.100.64.95:49265` to `94.72.252.234:8772` can be seen 

3. The physical offset is listed in the same line.

## Answers

### Question 1
- `94.72.252.87`

### Question 2 
- `hr_datasheet_allemp.csv`

### Question 3 
- `32`

### Question 4
- `8080`

### Question 5
- `0x123fac8b0`
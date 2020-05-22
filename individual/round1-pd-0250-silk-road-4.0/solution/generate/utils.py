"""
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
"""

from cryptography.fernet import Fernet
import gpxpy
import os
import random

d = []
for _, directories, _ in os.walk("../output"):
    for directory in directories:
        d.append(directory)
print(random.choice(d))

exit(0)
# thefile = open("solution/j.gpx").read()
# gpx = gpxpy.parse(thefile)
# if(len(gpx.tracks) > 0):
#     for track in gpx.tracks:
#         for segment in track.segments:
#             for point in segment.points:
#                 print(point)
# exit(0)

# key = Fernet.generate_key()
key = b'6A_z2lM7jTJjIM2kfKjWDPi3eqSwciMOjIVLzyOU88M='
print(key)
cipher_suite = Fernet(key)

text = b"""Ross Ulbricht, the 
hiking, 
yoga-loving libertarian convicted of masterminding and running the online black market bazaar known as 
Silk Road, has been sentenced to life in prison.

Ross William Ulbricht was _. He grew up in the Austin metropolitan area where he was a Boy Scout and had _.
The fact that Ross Ulbricht was using the alias _ was first identified in mid-2013. 
He had used another nickname, _ to seek programming help on a forum where he had given his _.

In mid-2013, while tracking every move Ross Ulbricht made, the FBI found out that he was being blackmailed 
by _. He had reportedly hacked into _ and  had obtained a long list of names and identities of _, whom he threatened to expose.

It all ended when a _ resident picked up the _ and recognized _.


import os
import ?
import shutil
import ??

def lol():
    exit(errno.ENOTTY)


"""

cipher_text = cipher_suite.encrypt(text)
print("")
print("")
print("")
print("")

print(cipher_text)
print("")
print("")
print("")
print("")


plain_text = cipher_suite.decrypt(cipher_text)

print("")
print("")
print("")
print("")

print(plain_text)


print(cipher_suite.decrypt(b'gAAAAABdjl_KcDsE5mhhclOr1HnU8G9KTd7xSyHy7axuKBIyLAQKHeiaWqyo0c-ygi1I9JdKTbvpnxgK2vfX34WaSlAIq0ZemCuta4g1aWI8Ebohs5GSUfUV_XsN7LPm88Mdb603h936kAC8T9W2WFK50_v7H4F_n40YWKAl0YPphF9t8snUeEGDdJtgoQOz1WV6t_QQCXdBrIJOt0gRrwR8r7YbBoWpgpbMQF4Gxn9NJoocU8S2AHN4aP8x0NVF70OdbOvnhP2FR6EMLgV4feY_z5srFA5669-cIeo7v02uJFVGKMkbzIQwXuj_qaqGJDWe2GJJb35SCaTeW8SnWxtCfsIY9mot2AdlTqmuwLg-1FEeqX4yFl9OaqjI2DtGqhQRHQSwlodE1UCZD3B5mfJPJVva6lZcsO9-bYeW37LuAEOkhGAS-LSgUUTK9DX4J2Z8UWuQZIh2Nf-KV7XZ4vgjIYGNFdODaQvsD6LrDYC-jbY3RfMVCi8v2X7kgdra6LjYKF8g5VWkAzWd7-0DOFBv3qyC3nGkrcgqd7oJDgk8m-AGY99r6IP-4NymT_tE5tuj0VVRwhhMjmrlvt2wC7f0qPKbfanldLv5p4Sgym6hpaLA4A28dHpBLuMVJRHMfuN7gDv3cKgcj9rNXXp_4dK5_FdwCsZUm97r6k_zeIUw4hizbu7CgKQ6Mt2goo4KiqSl4ffXyy82NqpEdujqOmY7R2c-dVoN6O06ZZpoOSRtNEk4olnO9b6U27y9z1YaePezRXz2n9vopSOgVHWw2mPhqDAEofZrxRc8Y75eyu4yQSRHbj2f3q0Rc89ulL02V4e2Alu7co9T0fHhVqL2fLtz9dTRbUh8o6zgZ4dLj8lrprXPWDeHmyRvjF2hTQLVNi-0jvDOTxWIGI0YAbmJjrmnKEO9FcjLqRbEvEHpHAy6OX5R2mWdkHz27WiYMf5-af0OZLNKAtkCWydr2Ng9T_qZxvkW8nOpONztqFrLT0HY2sCVsUZdE64inHfT_TSaUtWX5ZorvtjZMGPmlpabEr4aAGm3eKziyRnNcoDFtQ8t2FItlUJkoc0ymkivP7IVG9pAFLp_IyQJvF34CsogoE-EoPnKBw_XCO0hI1OTnoyNi69d0N-1a3asgN9tzjx2bFCsOo2YP-r0YYOP_C7EyWHEEYKw2LorCe1ikg5KZzWF8febLJraxpEc2EAg6XByoq6NEZ2dVbiW'))

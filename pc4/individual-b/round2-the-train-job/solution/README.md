# The Train Job

_Solution Guide_

## Overview

This challenge demonstrates that it can be very tricky to lock down Python enough that it is possible to allow access to create useful scripts without opening significant vulnerabilities - even with a restricted subset. The first part takes advantage of the fact that it is possible to access *imports of imports* in Python - in this challenge, there is a signing key that is being passed as command line arguments and competitors need to retrieve it. The second part is simple once the key has been retrieved - forge a JWT to tell the server to move the train.

## Question 1

_What is the signing key the scheduling server uses to authenticate with the train operation server?_

This challenge can be solved simply, with the right understanding of Python. `client.py` is a simple script that uploads a file named `schedule.py` to a server. Competitors are not given the source for the server itself, but they are given the code for `runner.py`.

The runner script makes heavy use of `RestrictedPython` to limit the capabilities of the uploaded `schedule.py`. However, there is a critical flaw in this code: it is possible to import certain modules that appear innocuous but allow the access of more information than intended.

Experimentation with the server's response shows that it captures the output of the running script and returns it back to the requester.

* In the `move_train` function, the first line is retrieving a JWT signing key from the command line using `sys.argv`.
* In the `ALLOWED_IMPORTS` set, several of the allowed imports have also imported the `sys` module.
* We can put the above facts together and devise a `schedule.py` to retrieve the signing key:

```
import typing

print(typing.sys.argv)
```

This small script will print out the command line arguments to the runner script and the server will blindly send it back to get the first flag.

## Question 2

_What is the token returned by the train operation server upon moving the train to the destination Miracle Colony?_

Now we need to get the train to move. The runner script reveals exactly how to do this in the `move_train` function. Depending on when you are solving this challenge, the `python-jose` package is either provided on the challenge server, or you will need to install it yourself.

* Install `python-jose` with `pip install python-jose`.
* Create the following script and run it (replace the string assigned to KEY with the key you got from part 1):
```
from jose import jwt
import requests


KEY = "01234567890abcdef"
token = jwt.encode({"aud": "3"}, KEY, algorithm="HS256")
r = requests.post(
    "http://challenge.us:8001/train/move",
    params={"destination": "Miracle Colony"},
    headers={"Authorization": f"Bearer {token}"}
)
print(r.text)
```
This should print the second flag.

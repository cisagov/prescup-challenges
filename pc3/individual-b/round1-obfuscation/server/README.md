# Server

This server has been slightly modified from its original version during the competition. Instead of listening on all available interfaces on port 5000, it listens on localhost only, on port 8000. It has also been updated so that successful completion results in a pseudo-flag saying "Success" (padded in the case of one part).

# Running the Server

You can use `pipenv` to install the required packages as shown [here](https://www.pythontutorial.net/python-basics/install-pipenv-windows/). Otherwise, you just need a Python 3.7+ environment which has both `flask` and `pycryptodome` installed.
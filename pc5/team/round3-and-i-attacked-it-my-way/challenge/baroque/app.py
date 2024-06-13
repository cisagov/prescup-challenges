#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, os
from app import create_app


app = create_app()
if __name__ == '__main__':
    app.run("0.0.0.0", ssl_context=(f"{os.path.abspath(os.path.dirname(__file__))}/app/ssl/cert.pem",f"{os.path.abspath(os.path.dirname(__file__))}/app/ssl/key.pem"), port=443, debug=False)

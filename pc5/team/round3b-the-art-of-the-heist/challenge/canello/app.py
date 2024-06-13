#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, os
from funcs import create_app

if __name__ == "__main__":
    app = create_app()
    app.run("0.0.0.0",port=80, debug=False)

#!/usr/bin/python

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from flask import Flask
from flask import request

app = Flask( __name__ )

@app.route( '/monster' )
def monster():
    if request.args.get('c') is not None:
        print( 'cookie text: ' + request.args.get('c'))
        return 'hello world'
    else:
        return 'nothing to see here move along'


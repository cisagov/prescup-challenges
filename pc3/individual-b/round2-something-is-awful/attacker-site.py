#!/usr/bin/python

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

## This website is used as part of grading. 
# The website will receive data (via GET requests) from the simulated attacker that is used for grading


from flask import Flask
from flask import request

app = Flask( __name__ )

@app.route( '/monster' )
def monster():
    if request.args.get('c') is not None:
        #print( 'cookie text: ' + request.args.get('c'))
        file1 = open("/tmp/defend.txt", "a")  # append mode
        file1.write( request.args.get('c') + "\n")
        file1.close()
        return 'hello world'
    else:
        return 'nothing to see here move along'

app.run(port=5100)


# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from  flask import Flask
from flask import session
from flask import request
from flask import redirect
from flask import url_for

app = Flask( __name__ )

@app.route( "/" )
def index():
	return 'visit /monster.'


@app.route( '/monster' )
def listing():
	if request.args.get('c') is not None:
		print( 'cookie text: ' + request.args.get('c') )
		return '<h1>Hello world!</h1>'
	return 'nothing to see here, move along'




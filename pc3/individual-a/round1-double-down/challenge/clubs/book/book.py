
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#!/usr/bin/python3

from flask import Flask, render_template

app=Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    # renders the home page
       return render_template('index.html')

# server is enabled, read grading script variable and start server
app.run(host='0.0.0.0', port=80, debug=False)



# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from flask import Flask, request, render_template_string, make_response
import os, sys
app = Flask(__name__)

@app.route('/', methods=['GET'])
def hello():
    name = request.args.get('name', 'World!<br>Enter your name in the URL Parameter called \"name\"')
    
    template = '''<h1>Hello %s!</h1>\n''' % name
    if "World" not in name:
        template += '''<h2>Instructions: {{get_file_content("instructions.txt")}}</h2>\n'''
    return render_template_string(template)


####
# Private function
###
def get_file_content(f_name):
    with open(f_name) as f:
	    return f.readlines()

app.jinja_env.globals['get_file_content'] = get_file_content # Allows for use in Jinja2 templates


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)





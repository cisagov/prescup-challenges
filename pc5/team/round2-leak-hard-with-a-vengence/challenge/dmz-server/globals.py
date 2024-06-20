#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from ast import expr
import os, sys, subprocess, json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import table, column, select, create_engine, text
from models import Comment, Post, File
from flask import g, request
from __init__ import db

def runExpression(statement):
    enteredExpression = text(statement)
    try:
        expRes = db.session.execute(enteredExpression).all()
        return expRes
    except Exception as e:
        error = [f"Error found: Unable to process query."]
        return error


pageNotFound='''
{% extends 'base.html' %}
{% block content %}
<div class="center-content error">
    <center>
        <h1>Oops! That page doesn't exist.</h1>
        <h3>%s</h3>
    </center>
</div>
{% endblock %}
'''

blogHomePage='''
{% extends 'base.html' %}
{% block content %}
<div>
    <center>
        <h1><u>Anonymous Blog</u></h1>
        <h2>Welcome to an unrestricted and free anonymous blogging site. Lets get chatting</h2>
    </center>
</div>
{% endblock %}
'''

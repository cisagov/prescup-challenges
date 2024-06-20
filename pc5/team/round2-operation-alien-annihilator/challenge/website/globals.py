#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from ast import expr
import os, sys, subprocess, json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import table, column, select, create_engine, text
from models import User, File
from flask import g, request
from __init__ import db

# templates
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

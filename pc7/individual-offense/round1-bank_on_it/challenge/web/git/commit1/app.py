import hashlib
import pymysql
from flask import Flask, request, redirect, url_for,  render_template, make_response
from tinydb import TinyDB, Query
import os
import logging

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run()
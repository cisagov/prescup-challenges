#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, subprocess, json

# thread list
global thread_tracker
thread_tracker = dict()

# templates
pageNotFound='''
<div class="center-content error">
    <center>
        <h1>Oops! That page doesn't exist.</h1>
        <h3>%s</h3>
    </center>
</div>
'''

home_page='''
<div>
    <center>
        <h1><u>Sensor Control Center</u></h1>
    </center>
</div>
'''


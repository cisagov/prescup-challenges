#!/usr/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

v=0

cd /usr/share/prescup

tar xfJ repo_v$v.tar.xz

cd web

python3 -m http.server 8000


#!/usr/bin/python3

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from __init__ import create_app, db

if __name__ == '__main__':
    app = create_app()
    db.create_all(app=create_app())
    app.run(host='0.0.0.0',port=5000, debug=True)

#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from app import create_app

app = create_app()
if __name__ == '__main__':
    app.run("0.0.0.0", port=5000, debug=False)

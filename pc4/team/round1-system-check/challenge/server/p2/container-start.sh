#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

sudo docker run -p 1235:1234 -v $(pwd)/local.db:/app/local.db --restart always -d r1-teams-p2

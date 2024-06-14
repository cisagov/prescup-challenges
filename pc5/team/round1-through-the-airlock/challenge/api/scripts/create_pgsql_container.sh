#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


sudo docker run --name postgres -e POSTGRES_PASSWORD=009f5f361cf66e2e -p 5432:5432 --rm -d postgres

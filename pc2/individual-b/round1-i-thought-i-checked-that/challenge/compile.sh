#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

gcc -pedantic -fno-stack-protector --std=gnu99 -no-pie -o challenge.elf ./vuln.c

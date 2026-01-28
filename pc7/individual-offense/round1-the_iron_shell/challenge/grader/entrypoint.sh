#!/bin/bash

sed -i "s|abcedf|${token2}|" /grader.py

python3 /grader.py
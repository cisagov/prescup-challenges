#!/bin/bash

set -e
npm install -g codedown
cat README.md | codedown python > solution.py
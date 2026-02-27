#!/usr/bin/env bash
# This is only needed for the solution script
python3 -m venv venv
source venv/bin/activate
ipython kernel install --user --name=solution_venv
echo "May need to restart VSCode for this to work"
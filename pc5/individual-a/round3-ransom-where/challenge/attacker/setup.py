
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from distutils.core import setup
#import py2exe
import sys

from glob import glob

# sys.path.append("C:")
# data_files = [
#     ("msvcp100", glob(r'.\*.dll'))]
setup(
    # data_files=data_files,
    windows=['main.py']
)


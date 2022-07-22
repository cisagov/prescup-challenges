
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import glob
import os
import shutil
import sqlite3

"""
(1) determine which files are in play, as it is, just the sqlite database is needed to get started, the rest of the files hopefully just get in the way
(2) extracting the correct database table provides a lot more files as an entirely separate structure of files
(2a) we can use python to extract them to the structure indicated in the database
(3) but several files are missing and can be located back in the original structure, these need to be added to the decrypt tree
(4) iterate the solution method several times over the tree for the flag file
"""

appbasepath = "/media/cdrom0/"
temp_dir = "_temp/"
database_file = "_magic_jar.sqlite"

def get_directories():
    files = glob.glob(temp_dir + "**/*.txt", recursive=True)
    directories = []
    for f in files:
        directories.append(os.path.dirname(f))
    directories.sort()
    directories = set(directories)
    return directories


def process_folder(directories):
    for directory in directories:
        print(directory, end='\r')
        for f in glob.glob(directory + "/*.txt"):
            shutil.move(f, str.replace(f, ".txt", ".phylactery"))
        os.system("cd " + directory + " && phylactery bind .")
        for f in glob.glob(directory + "/*.phylactery"):
            os.remove(f)
        for f in glob.glob(directory + "/*.*"):
            print("f:" + f, end='\r')
            print("d:" + os.path.dirname(f), end='\r')
            print("p:" + os.path.splitext(f)[0], end='\r')
            print("x:" + os.path.dirname(f) + os.path.basename(f), end='\r')
            shutil.move(f, os.path.dirname(f) + os.path.basename(f))
            os.removedirs(os.path.dirname(f))


def process_database():
    i = 0
    print("processing database at: " + appbasepath + "documents/" + database_file)
    db = sqlite3.connect(appbasepath + "documents/" + database_file)
    cursor = db.cursor()
    cursor.execute("SELECT o_id, group_id, data FROM documents")
    for row in cursor.fetchall():
        filename = row[0]
        filepath = temp_dir + row[1] + "/"
        data = row[2]
        if not os.path.exists(filepath):
            try:
                print("making dir: " + filepath)
                os.makedirs(filepath)
            except OSError as exc: # Guard against race condition
                print("EXC: " + exc)
        filename = filepath + str(filename) + ".txt"
        print(filename, end='\r')
        if not os.path.isfile(filename):
            with open(filename, "wb") as f:
                f.write(data)
                i += 1
    print("Wrote {} files".format(i))

print("Solving...")

if not os.path.exists(temp_dir):
    process_database()

i = 1
while os.path.exists(temp_dir):
    print("\nunwinding spell " + str(i))
    process_folder(get_directories())
    i += 1

with open("_temp0.file", "r") as f:
    print("\n\n" + f.read() + "\n\n")

print("Banish ye to the outer planes! I AM A WORTHY ADVERSARY.")


"""
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
"""

import csv
import itertools
import zipfile

part1 = []
part2 = []
part3 = []
part4 = []

with open('Problem9.csv') as csvDataFile:
    csvReader = csv.reader(csvDataFile)
    # Skip header row
    next(csvReader)
    for row in csvReader:
        part1.append(row[0])
        part2.append(row[1])
        part3.append(row[2])
        part4.append(row[3])


z = zipfile.ZipFile('Problem9.zip')

for a, b, c, d in itertools.product(part1, part2, part3, part4):
    pswd = a+b+c+d
    try:
        z.extractall(pwd=pswd.encode())
    except (RuntimeError, zipfile.BadZipfile):
        continue
    else:
        print(pswd)
        break

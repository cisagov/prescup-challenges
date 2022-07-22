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

import os
from random import sample, shuffle
import sys

bad_path = os.path.join('src', 'functions', 'bad')
good_path = os.path.join('src', 'functions', 'good')

bad = os.listdir(bad_path)
good = os.listdir(good_path)

choices = []

choices.extend(sample(bad, len(bad)//2))
choices.extend(sample(good, len(good)//2))

shuffle(choices)


code = []

for i, item in enumerate(choices):
    if item in bad:
        path = os.path.join(bad_path, item)
    elif item in good:
        path = os.path.join(good_path, item)

    with open(path) as f:
        function = f.read()

    function = function.replace('placeholder', 'func' + str(i))
    code.append(function.strip())

functions_content = '\n\n####\n\n'.join(code)
flag = ''.join(choices)

with open('/dst/.gen_files', 'w') as f:
    f.write('/dst/functions.txt')

with open('/dst/functions.txt', 'w') as f:
    f.write(functions_content)

with open('/dst/flag.txt', 'w') as f:
    f.write(flag)

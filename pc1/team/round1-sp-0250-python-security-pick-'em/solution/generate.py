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

from random import choice, shuffle

bad_pool = ['bfile1.txt','bfile2.txt','bfile3.txt','bfile4.txt','bfile5.txt',
'bfile6.txt','bfile7.txt','bfile8.txt','bfile9.txt','bfile10.txt']

good_pool = ['gfile1.txt','gfile2.txt','gfile3.txt','gfile4.txt','gfile5.txt',
'gfile6.txt','gfile7.txt','gfile8.txt','gfile9.txt','gfile10.txt']

choices = []

while(len(choices) < 5):
  candidate = choice(bad_pool)
  if(candidate not in choices):
    choices.append(candidate)

while(len(choices) < 10):
  candidate = choice(good_pool)
  if(candidate not in choices):
    choices.append(candidate)

shuffle(choices)
#print(choices)

# Change this path on the generation server
#path = '/home/pcup-admin/PCup/SP500-T1/functions/'
path = '/src/functions/'

# Generate the flag
flag = ''
for filename in choices:
  path_file = path + filename
  with open(path_file) as fp:
    if('b' in filename):
      line = list(fp)[4]
    else:
      line = list(fp)[2]
    piece = line.split('\'')[1][0:2]
    flag += piece

# Generate the code for analysis
footer = ''
code = ''
code += 'flag = \'\'\n\n'

headers = {
  'bfile2.txt' : '(filename):\n',
  'bfile3.txt' : '(file):\n',
  'bfile5.txt' : '(file_list=[]):\n',
  'bfile6.txt' : '(file, user):\n',
  'bfile8.txt' : '(password):\n',
  'bfile10.txt' : '(file, extraction_path):\n',
  'gfile2.txt' : '(low, high):\n'
}

for x in range(10):
  code += '###################\n\n'
  if(choices[x] in headers.keys()):
    header = 'def func' + str(x) + headers[choices[x]]
  else:
    header = 'def func' + str(x) + '():\n'

  code += header
  fp = open(path + choices[x], 'r')
  function = fp.read()
  code += function + '\n'

code += '###################\n\n'

with open('/dst/.gen_files', 'w') as file:
  file.write('/dst/functions.txt')

with open('/dst/functions.txt', 'w') as file:
  file.write(code)

with open('/dst/flag.txt', 'w') as file:
  file.write(flag)

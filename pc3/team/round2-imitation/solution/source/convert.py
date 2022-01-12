
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

""" Converts vkeys.txt into Rust code so I can easily implement it """

filepath = 'vkeys.txt'
code = ''
num = ''
string = ''

array = {}

with open(filepath) as fp:
    line = fp.readline()
    cnt = 0
    while line:
        if cnt == 0:
            code = line.strip()
            cnt += 1
        elif cnt == 1:
            num = line.strip()
            cnt += 1
        else:
            cnt = 0
            string = line.strip()
            array[int(num, 16)] = f'"{code}",'
            #print(num, "=> { \"" + code + "\".to_string() }")

        line = fp.readline()

for i in range(256):
    if (65 <= i <= 90) or (48 <= i <= 57):
        out_char = f'"{chr(i)}",'
    else:
        out_char = f'"CODE_{hex(i).upper()}",'
    print(array.get(i, out_char))

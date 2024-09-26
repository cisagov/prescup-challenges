#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, subprocess, json
import pandas as pd
from odf import text, teletype
from odf.opendocument import load

### PLEASE READ
# This script has been altered to work locally on your machine with the assumption that it follows the structure used in the online repository.
# When running this script, you will need to submit each script as an argument. Below is an example of how it can be executed.
# 
# The example grading command below will assume the 4 scripts have been created and are named: `hill_cipher.py`, `convert.py`, `morse.py`, and `pin.py` 
# the 1st passed arg will always grade against the Hill Cipher task
# the 2nd passed arg will always grade against the Conversion task
# the 3rd passed arg will always grade against the Morse Code task
# the 4rd passed arg will always grade against the Pin Code task
# `python3 gradingScript.py 'python3 hill_cipher.py' 'python3 convert.py' 'morse.py' 'pin.py'
# 
## NOTE: 
# If you face errors, you can manually do the grading check without this script by following these steps
# task 1 -- Hill Cipher
#   1. Run the decryption function in your Hill Cypher script with the encrypted string "vvnbqrx vdwgvhto" and key "heroheroo".
#   2. The expected output is "protect hyrulezz". If it matches, this task is complete.
# task 2 -- File Conversion
#   part 1: PNG -> TXT
#       1. Run your file converter script against the file `./task_files/t3/c1.png` and attempt to convert it to `txt` with the output being `c1.txt`
#       2. If the content in `c1.txt` matches the content in `c1.png`, this part is correct.
#   part 2: PDF -> ODT
#       1. Run your file converter script against the file `./task_files/t3/c2.pdf` and attempt to convert it to `odt` with the output being `c1.odt`
#       2. If the content in `c1.pdf` matches the content in `c1.png`, this task is complete.
# task 3 -- Morse Code
#   1. Run the encryption function in your Morse Code script against the plain string "Mr. Green, candlestick, in the observatory." and output it to some filename (ex: 'morse_mapping'). Save the encrypted string that was output.
#   2. Run the decryption function in your morse code script against the encrypted string output above and the input file being the file you wrote out to. (ex: 'morse_mapping').
#   3. If the output from the decryption matches the original plain string, this task has been completed.
# task 4 -- Pin Code
#   1. Run your pin script with the pin code `D2B9F` and the output path to some file. (ex: pin_list)
#   2. Check the pins generated in the output file against the pins present in the `./task_files/t5/combos`. 
#       - the correct number of total combinations is 17496 for reference.
#   3. If they match, this task is completed.
###

# Hill cipher
def t1(hostname, cmd1, task_check):
    try:
        output = subprocess.run(f"{cmd1} d \"{task_check['encrypted']}\" {task_check['key']}",shell=True,capture_output=True)
    except Exception as e:
        err = e.replace(task_check['encrypted'], '---').replace('\n','')
        return f"Failure -- Error occurred while running command. Error message -- {err}"
    if "No such file" in output.stderr.decode('utf-8'):
        return "Failure -- Entered file cannot be found. Please check input and try again."
    status = ''
    if task_check['plain'] == output.stdout.decode('utf-8').strip('\n'):
        status = "Success"
    elif output.stderr.decode('utf-8') != '':
        err = output.stderr.decode('utf-8').replace(task_check['encrypted'], '---').replace('\n','')
        status = f"Failure -- Script exited with error. Error Message -- {err}"
    else:
        err = output.stdout.decode('utf-8').replace(task_check['encrypted'], '---').replace('\n','')
        status = f"Failure -- Script Output --  {err}"
    return status

# convert file
def t2(hostname, cmd3, task_check):
    for key, value in task_check.items():
        #subprocess.run(f"sshpass -p 'tartans' scp -o 'StrictHostKeyChecking=no' {value['original'][0]} user@{hostname}:/home/user/Documents/",shell=True,capture_output=True).stdout.decode('utf-8')
        try:
            output = subprocess.run(f"{cmd3} ./task_files/t3/c1.png {value['converted'][2]} ./converted_files/",shell=True,capture_output=True)
            if 'converted_files' not in os.listdir('./'):
                os.system("mkdir 'converted_files'")
        except Exception as e:
            return f"Failure -- Error occurred while running command. Error message -- {str(e)}"
        if "No such file" in output.stderr.decode('utf-8'):
            return "Failure -- Script did not create the expected output file. Please check input and try again."
    # grade files sent back
    for k,v in task_check.items():
        file_content = ''
        if k == 'c1':
            try:
                with open(f"./converted_files/{v['converted'][1]}", "r") as f:
                    file_content = f.read()
            except:
                return "Failure -- Unable to find/read converted TXT file. Please verify script executes correctly and try again."
        else:
            try:
                doc = load(f"./converted_files/{v['converted'][1]}")
            except:
                return "Failure -- Unable to find/read converted ODT file. Please verify script executes correctly and try again."
            content = []
            for para in doc.getElementsByType(text.P):
                content.append(teletype.extractText(para))
            file_content = ' '.join(content)
        if v['answer'] not in file_content:
            return f"Failure -- Text missing from original file."
    return "Success"


# Morse code
def t3(hostname, cmd4, task_check):
    status = ''
    try:
      output = subprocess.run(f"{cmd4} encrypt \"{task_check['plain']}\" ./converted_files/test4",shell=True,capture_output=True)
    except Exception as e:
        return f"Failure -- Error occurred while running entered command. {str(e)}"
    updated_out = output.stdout.decode('utf-8').strip()
    updated_err = output.stderr.decode('utf-8')
    status += f"Stdout from {cmd4}: {updated_out} -- Stderr from {cmd4}: {updated_err}"
    if updated_err != '':
        status = "Failure -- " + status
        return status
    reverse_check = subprocess.run(f"{cmd4} decrypt \"{updated_out}\" ./converted_files/test4",shell=True,capture_output=True)
    if reverse_check.stdout.decode('utf-8').strip().lower() == task_check['plain'].lower():
        return "Success"
    elif reverse_check.stdout.decode('utf-8').strip().lower() != task_check['plain'].lower():
        return "Failure -- Decryption of encrypted string does not match original input."
    elif reverse_check.stderr != '':
        return f"Failure -- Stdout from {cmd4}: {updated_out} -- Stderr from {cmd4}: {updated_err}"
    else:
        return "Failure -- Grading did not produce expected output"
    #return status

# pin code
def t4(hostname, cmd5, task_check):
    try:
        output = subprocess.run(f"{cmd5} {task_check['pin']} ./pin_list",shell=True,capture_output=True)
    except Exception as e:
        return f"Failure -- Error occurred while running entered command. {str(e)}"
    if "No such file" in output.stderr.decode('utf-8'):
        return "Failure -- Entered file cannot be found. Please check input and try again."
    with open(task_check['combinations'], 'r') as f:
        correct_combos = f.readlines()
    try:
        with open('./task_files/t5/combos', 'r') as f:
            test_combos = f.readlines()
    except:
        return "Failure -- script did not produce the expected output file."
    
    check = all(p in test_combos for p in correct_combos)

    if check == True:
        return "Success"
    return "Failure -- Created combination list has missing and/or incorrect entries."


def start_grade(args):
    # create arg_dict to store the text entered for each task.
    arg_dict = dict()
    for x in range(len(args)):
        arg_dict[f't{x+1}'] = args[x]
    results = dict()
    # task = t1, t2, t3, etc. to track each tasks grading
    # arg = the input that was entered into the text box on the grading server grading page
    task_checks = ''
    with open("./task_checks", 'r') as f:
        task_checks = json.loads(f.read())
    for task,arg in arg_dict.items():
        if (arg == None) or (arg == ''):
            results[task] = 'Failure'
            continue
        try:
            hostname, cmd = arg.split('::')
        except Exception as e:
            results[task] = f"Unable to parse Hostname and command entered. Please verify '::' is between hostname and command and try again."
            continue
        else:
            results[task] = globals()[task](hostname, cmd.strip('\n'),task_checks[task])
    for t,r in results.items():
        print(t, ' : ', r) 
    

if __name__ == '__main__':
    start_grade(sys.argv[1:])

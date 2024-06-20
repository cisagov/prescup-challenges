#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, sys, json, random
from pathlib import Path



original = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "'": ".----.",
    "!": "-.-.--",
    "/": "-..-.",
    "(": "-.--.",
    ")": "-.--.-",
    "&": ".-...",
    ":": "---...",
    ";": "-.-.-.",
    "=": "-...-",
    "+": ".-.-.",
    "-": "-....-",
    "_": "..--.-",
    "\"": ".-..-.",
    "$": "...-..-",
    "@": ".--.-."
}
og_keys = list(original.keys())
og_vals = list(original.values())

def randomize():
    random.shuffle(og_keys)
    random.shuffle(og_vals)
    morse_map = dict()
    for k,v in zip(og_keys, og_vals):
        morse_map[k] = v
    
    return morse_map, list(morse_map.values())

def convert(data, convert_to, filePath):
    if convert_to == 'encrypt':
        morse_map, morse_values = randomize()
        morse_str = ''
        # go through string and convert to morse code
        for char in data:
            if char == ' ':
                morse_str += '/ '
                continue
            morse_str += morse_map[char]+ ' '
        print(morse_str)  
        try:
            fp = Path(os.path.abspath(filePath))
            with open(fp, 'w+') as f:
                f.write(json.dumps(morse_map))
        except:
            print("error writing current Morse Code mapping to file. Exiting.")
            sys.exit()

    elif convert_to == 'decrypt':
        fp = Path(os.path.abspath(filePath))
        try:
            with open(fp, 'r') as f:
                morse_map = json.loads(f.read())
        except:
            print("error reading Morse Code mapping file. Exiting.")
            sys.exit()
        morse_values = list(morse_map.values())
        morse_keys = list(morse_map.keys())
        plain_str = ''
        # go through list of morse code entries 
        for str in data:
            if str == '/':
                plain_str += ' '
                continue
            current_mapping_index = morse_values.index(str)
            plain_str += morse_keys[current_mapping_index]
        print(plain_str)  # Encoded string:\n{' '.join(data)}

def check_contents(str_arg, convert_to):
    if convert_to == 'decrypt':
        # Create list by splitting string using spaces and check if all entries are in the morse code format. 
        str_list = str_arg.split(' ')
        tmp_list = str_list
        for s in tmp_list:
            if s == '/':
                continue
            if s not in og_vals:
                #print(f"Unknown string {s} not represented in morse code, removing character from string...\n")
                str_list.remove(s)
        return str_list
    elif convert_to == 'encrypt':
        tmp_str = str_arg
        for c in tmp_str:
            # verify all characters in plain text string are characters that can be converted to morse code.
            if c.isspace():
                continue
            if c not in og_keys:
                print(f"Unknown character {c} not represented in morse code, removing character from string...\n")
                str_arg = str_arg.replace(c,'')
        return str_arg
    # If both checks failed, then there is something weird in the file/string
    raise Exception("File contents format not specified. Please enter second argument specifying 'encrypt', or 'decrypt' to encrypt or decrypt respectfully.")
    

def verify_file(filename):
    filePathStr = os.path.abspath(filename)
    filePath = Path(filePathStr)
    if not filePath.is_file():
        raise Exception(f"Entered File: {filePath} does not exist or cannot be read. Please verify file and try again.")
    with open(filePath, 'r') as f:
        data = f.read().upper().strip('\r\n')
    if len(data) == 0:
        raise Exception("\nFile empty.")
    return data

if __name__ == '__main__':
    # arg1 is file containing message to be encrypted and/or decrypted, arg2 is the format you want the file converted too
    if len(sys.argv) != 4:
        raise Exception("\nScript requires 3 arguments. 1st is either 'encrypt' or 'decrypt'. 2nd is the string to be converted. 3rd is the file where the mapping will be written too or read from.")
    string_arg = sys.argv[2].strip('\n').upper()
    convert_to = sys.argv[1].strip('\n')
    filePath = sys.argv[3]
    data = check_contents(string_arg, convert_to)
    convert(data, convert_to, filePath)

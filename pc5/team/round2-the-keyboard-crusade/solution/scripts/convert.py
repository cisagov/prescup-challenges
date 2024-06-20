#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, os, subprocess, magic, json
from pathlib import Path

###
# Script requires the following commands to be installed:
# tesseract 
# pdftotext
###

##### 
# conversion_map explanation
# First key is the file type of the file that was passed to the script.
# The second key within the first, the key 'type' maps to the string that is returned when 'magic.from_file()' which is ran against the file passed to determine its filetype.
# All other keys within the first is the file type you can to convert too. ex: ['txt']['odt'] would convert txt -> odt
# Value of second keys are the commands needed to do the conversion..
# Example:  Want to convert png -> odt, 
# get the cmds required to complete this process by pulling the associated value at: conversion_map["png"]["odt"]
# Cmds for completing this would be to do: png --convert--> txt --convert--> odt
# fn == filename
# nn == new name
#####
conversion_map = {
    "txt": {
        "type":"text",
        "odt":{"path:dir":"libreoffice --convert-to odt {} --outdir {}"},      
        "png":{"path:dir":"libreoffice --convert-to png {} --outdir {}"},      
        "html":{"path:dir":"libreoffice --convert-to html {} --outdir {}"},    
        "pdf": {"path:dir":"libreoffice --convert-to pdf {} --outdir {}"}     
    },
    "png": {
        "type":"PNG image data",
        "txt":{"path:ext":"tesseract -l eng {} {} txt "},         
        "odt":{
            "path:ext":"tesseract -l eng {} {} txt",
            "path:dir":"libreoffice --convert-to odt {}  --outdir {}"},   
        "html":{
            "path:ext":"tesseract -l eng {} {} txt",
            "path:dir":"libreoffice --convert-to html {}  --outdir {}"}, 
        "pdf": {
            "path:ext":"tesseract -l eng {} {} txt",
            "path:dir":"libreoffice --convert-to pdf {} --outdir {}"}   
    },
    "odt": {
        "type":"OpenDocument",
        "txt": {"path:dir":"libreoffice --convert-to 'txt:Text (encoded):UTF8' {} --outdir {}"},
        "png": {
            "path:dir":"libreoffice --convert-to 'txt:Text (encoded):UTF8' {} --outdir {}",
            "path:dir:txt":"libreoffice --convert-to png {} --outdir {}"},
        "html":{"path:dir":"libreoffice --convert-to html {} --outdir {}"},
        "pdf": {"path:dir":"libreoffice --convert-to pdf {} --outdir {}"}
    },
    "html": {
        "type":"HTML",
        "txt": {"path:dir":"libreoffice --convert-to 'txt:Text (encoded):UTF8' {} --outdir {}"},
        "png": {
            "path:dir":"libreoffice --convert-to 'txt:Text (encoded):UTF8' {} --outdir {}",
            "path:dir:txt":"libreoffice --convert-to png {} --outdir {}"},
        "odt": {"path:dir":"libreoffice --convert-to odt {} --outdir {}"},
        "pdf": {"path:dir":"libreoffice --convert-to pdf {} --outdir {}"}
    },
    "pdf": {
        "type":"PDF document",
        "txt": {"path:ext":"pdftotext {} {}.txt"},
        "png": {"path:dir":"libreoffice --convert-to png {} --outdir {}"},
        "odt": {
            "path:ext":"pdftotext {} {}.txt",
            "path:dir:txt":"libreoffice --convert-to odt {} --outdir {}"},
        "html":{"path:dir":"libreoffice --convert-to html {} --outdir {}"}
    }
}

def convert(convert_dict):
    #print(json.dumps(convert_dict,indent=2))
    for key,cmd in convert_dict['cmds'].items():
        fn=opt=''
        opts = key.split(':')
        if len(opts) == 2:
            fn = convert_dict[opts[0]]
            opt = convert_dict[opts[1]]
        else:
            fn = convert_dict['dir']+'/'+convert_dict['ext'].rsplit('/',1)[1]+f'.{opts[2]}'
            opt = convert_dict[opts[1]]
        current_cmd = cmd.format(fn,opt)
        output = subprocess.run(current_cmd,shell=True,capture_output=True)
        if output.stderr.decode('utf-8') != '':
            return output.stderr.decode('utf-8')
    return "Commands executed successfully."

def check_args(filename, convertType, outputDir):
    # Verify the file passed exists.
    filePathStr = os.path.abspath(filename)
    filePath = Path(filePathStr)
    if not filePath.is_file():
        print("Entered file cannot be found and/or read. Please verify arguments and try again.")
        sys.exit()
    # verify the output directory passed is a valid location
    dirStr = os.path.abspath(outputDir)
    dirPath = Path(dirStr)
    if not dirPath.is_dir():
        print("Entered output directory not valid. Please verify arguments and try again.")
        sys.exit()
    localPath,extension = filename.rsplit(".", 1)
    # Verify that filetype of file entered is one that is valid for conversion
    if extension not in list(conversion_map.keys()):
        print("Filetype of file passed not available for conversion. Please try again with valid filetype")
        sys.exit()
    if any(convertType in fm for fm in list(conversion_map.keys())) == False:
        print("Filetype to be converted too not available for conversion. Please try again with valid filetype")
        sys.exit()
    cmds = list()

    
    for key in conversion_map:
        if extension == key:
            cmds = conversion_map[key][convertType]

    return {
        "path": filePathStr,                                        # full path to file we are converting
        "fn": filePathStr.rsplit('/',1)[1],                         # name of file with extension
        "ext": os.path.join(dirStr,filePathStr.rsplit('.',1)[0].rsplit('/',1)[1]),       # name of file without extension
        "convert": convertType,                                     # type we are converting too
        "dir": dirStr,                                              # directory we will write file too
        "cmds": cmds                                                # cmds being run to accomplish task
    }

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("3 arguments required.\n1st arg is the full file path with extension.\n2nd arg is the filetype you want to convert it to.\n3rd arg is the directory you want to the file written to.")
        sys.exit()
    convert_dict = check_args(sys.argv[1], sys.argv[2], sys.argv[3])
    results = convert(convert_dict)
    print(results)

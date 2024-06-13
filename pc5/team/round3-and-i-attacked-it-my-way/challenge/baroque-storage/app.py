#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, os, string, random
from flask import Flask, send_from_directory, request, render_template, jsonify, send_file, json

app = Flask(__name__)
api_key = "6fe12e33"

@app.route('/',methods=['GET','POST'],defaults={"filename":None})
@app.route('/<path:filename>',methods=['GET','POST'])         
def host_files(filename):
    if request.method == 'GET':
        fp = f"{os.path.abspath(os.path.dirname(__file__))}/static/"
        files = os.listdir(fp)
        if filename == None:
            return render_template("files.html",files=files)
        else:
            if filename not in files:
                return render_template("files.html",files=files,no_file='true') 
            return send_from_directory(fp, filename)
    else:
        data = request.form
        if len(data) == 0:
            return jsonify({"Error":"Form data missing."})
        if "api_key" not in list(data.keys()):
            return jsonify({"Error":"'api_key' not present and required for POST. Please contact the owner to get the API Key."})
        elif data['api_key'] != api_key:
            return jsonify({"Error":"Incorrect API Key received"})
        files = request.files
        if len(files) == 0:
            return jsonify({"Notice":"No files received for upload"})
        else:
            for file_entry in files:
                try:
                    file = files[file_entry]
                    fn = file.filename
                    if fn == '':
                        characters = string.ascii_letters + string.digits
                        fn = 'tmp' + ''.join(random.choice(characters) for i in range(16))
                        
                    path_to_save = f"{os.path.abspath(os.path.dirname(__file__))}/static/{fn}"
                    file.save(path_to_save)
                except Exception as e:
                    return jsonify({"File Upload Failed":str(e)})
                else:
                    return jsonify({"Status":"File uploaded"})

@app.route("/report",methods=['POST'])
def store_report():
    if request.remote_addr != '10.1.1.75':
        return jsonify({"Error":"Unauthorized Access Attempt"})
    report = request.form
    file_cnt = len(os.listdir(f'{os.path.abspath(os.path.dirname(__file__))}/reports/'))
    file_num = 1 if file_cnt == 0 else file_cnt+1
    with open(f'{os.path.abspath(os.path.dirname(__file__))}/reports/report{str(file_num)}', "w+") as f:
        f.write(json.dumps(report))
    return jsonify({"Status":"Success"})



if __name__ == '__main__':
    app.run("0.0.0.0", port=443, ssl_context=(f"{os.path.abspath(os.path.dirname(__file__))}/ssl/cert.pem",f"{os.path.abspath(os.path.dirname(__file__))}/ssl/key.pem"),debug=False)


# 

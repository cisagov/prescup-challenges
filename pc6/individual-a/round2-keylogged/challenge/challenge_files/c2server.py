import os
import glob
import subprocess
from flask import Flask, request
from datetime import datetime

os.environ["WERKZEUG_DEBUG_PIN"] = "off"

SAVE_DIR = "/var/log/keylogs"
os.makedirs(SAVE_DIR, exist_ok=True)

app = Flask(__name__)

app.config["DEBUG"] = True

@app.route('/hidden_token_page', methods=['GET'])
def hidden_token_page():
    HIDDEN_PAGE_TOKEN = subprocess.run('vmtoolsd --cmd "info-get guestinfo.token4"', shell=True, capture_output=True).stdout.decode('utf-8').strip()
    return HIDDEN_PAGE_TOKEN, 200

@app.route('/', methods=['GET'])
def index_page():
    filename = request.args.get("filename")

    if not filename:
        return "Query parameter 'filename' is missing!", 400

    filepath = os.path.join(SAVE_DIR, f"{filename}")
    
    with open(filepath, "r") as f:
        data = f.read()
        return data, 200

@app.route('/', methods=['POST'])
def upload_keylog_file():   
    if len(request.data) == 0:
        raise Exception('Payload is empty')

    data = request.data.decode('utf-8')
    filename = os.path.join(SAVE_DIR, f"{datetime.now().isoformat()}.txt")
    
    with open(filename, "w") as f:
        f.write(data)

    return 'OK', 200

if __name__ == '__main__':
    app.run(host="127.0.0.1",port=8080, debug=True)


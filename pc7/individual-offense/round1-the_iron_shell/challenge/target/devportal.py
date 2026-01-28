from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/ping", methods=["GET"])
def ping():
    ip = request.args.get("ip", "")
    result = os.popen("ping -c 1 " + ip).read()
    return "<pre>" + result + "</pre>"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000)

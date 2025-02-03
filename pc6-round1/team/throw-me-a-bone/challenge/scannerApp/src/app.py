#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
# DM25-0166#

from flask import Flask, request, render_template
from system_check import validate_and_check_host, check_system

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    ip = None
    if request.method == 'POST':
        ip = request.form['ip']

        host_check = validate_and_check_host(ip)
        if not host_check["valid_ip"]:
            result = {"error": "Invalid IP address"}
        elif not host_check["online"]:
            result = {"error": "Host is offline"}
        elif host_check["error"]:
            result = {"error": host_check["error"]}
        else:
            result = check_system(ip)

    return render_template('index.html', result=result, ip_address=ip)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5555, debug=False, ssl_context=('/home/user/challengeServer/src/ssl/merch-codes.pem', '/home/user/challengeServer/src/ssl/merch-codes-key.pem'))
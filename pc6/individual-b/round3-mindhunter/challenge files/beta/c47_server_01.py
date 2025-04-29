from flask import Flask, request, jsonify, render_template
import requests
import json
import os
import threading
import re
import time
import random
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def get_guestinfo_tokens():
    """Retrieve guestinfo tokens using vmtoolsd on the local system."""
    tokens = []
    for i in range(1, 5):
        result = subprocess.run(
            ["vmtoolsd", "--cmd", f"info-get guestinfo.token{i}"],
            capture_output=True,
            text=True,
            check=True
        )
        tokens.append(result.stdout.strip())
    return tokens

def ssh_execute(ssh, command):
    """Execute a command via SSH and print the output."""
    stdin, stdout, stderr = ssh.exec_command(command)
    stdout.channel.recv_exit_status()
    output = stdout.read().decode()
    error = stderr.read().decode()
    if output:
        print(f"{output}")
    if error:
        print(f"{error}")


def create_app(port, name, required_headers=None, next_headers=None, required_tokens=None):
    app = Flask(name, template_folder='templates', static_folder='static')
    limiter = Limiter(app, key_func=get_remote_address, default_limits=["10 per minute"])  # Basic rate-limiting
    
    @app.route('/')
    def index():
        return render_template(f'{name}.html', title=f"{name} - Portal", image_url=f'/static/{name}.jpg')
    
    def check_headers():
        if required_headers:
            for key, value in required_headers.items():
                if request.headers.get(key) != value:
                    return False
        return True
    
    def check_tokens():
        if required_tokens:
            received_tokens = request.headers.get("X-Auth-Tokens")
            if not received_tokens:
                return False
            received_tokens = received_tokens.split(",")
            return all(token in received_tokens for token in required_tokens)
        return True
    
    def check_ip():
        client_ip = request.remote_addr
        if not re.match(r'^10\.6\.', client_ip):
            return False
        return True
    
    if name == "mirror1":
        @app.route('/fetch', methods=['GET'])
        @limiter.limit("5 per minute")
        def ssrf():
            if not check_headers() or not check_ip():
                return jsonify({"error": "Unauthorized Access"}), 403
            target = request.args.get("url")
            if not target:
                return jsonify({"error": "No URL provided"}), 400
            
            if re.match(r'^(http|https)://(127\.0\.0\.1|localhost|10\.|192\.168\.)', target):
                return jsonify({"error": "Access Denied"}), 403
            
            try:
                time.sleep(random.uniform(0.5, 2.0))
                response = requests.get(target, timeout=2)
                return jsonify({"response": response.text, "next_headers": next_headers, "token": "TOKEN-1-{ssrf_bypass}"})
            except Exception as e:
                return jsonify({"error": str(e)})
    
    if name == "mirror2":
        @app.route('/pollute', methods=['POST'])
        @limiter.limit("3 per minute")
        def prototype_pollution():
            if not check_headers() or not check_tokens() or not check_ip():
                return jsonify({"error": "Unauthorized Access"}), 403
            data = request.get_json()
            if isinstance(data, dict) and "__proto__" in data:
                time.sleep(random.uniform(0.5, 2.0))
                return jsonify({"token": "TOKEN-2-{proto_pollution}", "next_headers": next_headers})
            return jsonify({"error": "Invalid exploit"})
    
    if name == "mirror3":
        @app.route('/deserialize', methods=['POST'])
        @limiter.limit("2 per minute")
        def deserialize():
            if not check_headers() or not check_tokens() or not check_ip():
                return jsonify({"error": "Unauthorized Access"}), 403
            try:
                data = json.loads(request.data)
                if "execute" in data and isinstance(data["execute"], dict) and "cmd" in data["execute"]:
                    cmd = data["execute"]["cmd"]
                    if not re.match(r'^[a-zA-Z0-9_-]+$', cmd):
                        return jsonify({"error": "Invalid command"}), 403
                    allowed_dir = '/tmp/restricted/'
                    if not os.path.exists(allowed_dir):
                        os.makedirs(allowed_dir)
                    output_file = os.path.join(allowed_dir, 'token.txt')
                    with open(output_file, 'w') as f:
                        f.write("TOKEN-3-{custom_json_exploit}")
                    time.sleep(random.uniform(1.0, 3.0))
                    return jsonify({"message": "Command executed in sandbox", "path": output_file, "next_headers": next_headers})
            except Exception:
                return jsonify({"error": "Malformed request"})
            return jsonify({"error": "Exploit failed"})
    
    if name == "mirror4":
        @app.route('/race', methods=['POST'])
        @limiter.limit("1 per minute")
        def race_condition():
            if not check_headers() or not check_tokens() or not check_ip():
                return jsonify({"error": "Unauthorized Access"}), 403
            time.sleep(random.uniform(2.0, 5.0))
            if request.form.get("exploit") == "race_condition":
                return jsonify({"token": "TOKEN-4-{race_condition}"})
            return jsonify({"error": "Exploit failed"})
    
    return app, port

proxy_headers = {
    "mirror1": {"X-Forwarded-Auth": "stage1key"},
    "mirror2": {"X-Forwarded-Auth": "stage2key"},
    "mirror3": {"X-Forwarded-Auth": "stage3key"},
    "mirror4": {"X-Forwarded-Auth": "finalstage"}
}

mirror_apps = {
    "mirror1": create_app(5001, "mirror1", None, proxy_headers["mirror2"], None),
    "mirror2": create_app(5002, "mirror2", proxy_headers["mirror1"], proxy_headers["mirror3"], ["{TOKEN-1-{ssrf_bypass}}"]),
    "mirror3": create_app(5003, "mirror3", proxy_headers["mirror2"], proxy_headers["mirror4"], ["TOKEN-1-{ssrf_bypass}", "TOKEN-2-{proto_pollution}"]),
    "mirror4": create_app(5004, "mirror4", proxy_headers["mirror3"], None, ["TOKEN-1-{ssrf_bypass}", "TOKEN-2-{proto_pollution}", "TOKEN-3-{custom_json_exploit}"])
}

def setup_environment():
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)

def main():
    try: 
        setup_environment()
    except Exception as e:
        print(f"⚠️ Unable to set up environment - Error: {e}")
        exit(0)

    try: 
        tokens = get_guestinfo_tokens()
        print(f" ## // TOKEN VALUES // ##\r\n")
        token1 = tokens[0]
        token2 = tokens[1]
        token3 = tokens[2]
        token4 = tokens[3]
        print(f"✅ Token 1: {token1} \r\n")  
        print(f"✅ Token 2: {token2} \r\n")  
        print(f"✅ Token 3: {token3} \r\n")  
        print(f"✅ Token 4: {token4} \r\n")  
    except Exception as e:
        print(f"⚠️ Token generation was not successful. Exception: {e}")
        exit(0)        

    try: 
        threads = []
        for name, (app, port) in mirror_apps.items():
            t = threading.Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': port})
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
    except Exception as e:
        print(f"⚠️ Can't fork and make multiple servers. Exception: {e}")
        exit(0)


if __name__ == "__main__":
    main()

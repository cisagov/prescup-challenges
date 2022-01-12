
# source https://github.com/realpython/materials/tree/master/python-sockets-tutorial
## source material provided under MIT License: https://github.com/realpython/materials/blob/master/LICENSE

import socket
import sys
import selectors
import json
import io
import struct
import binascii
import datetime
import uuid
import os


#pcap api key -- "167e69d2-94b3-49b4-b19f-63da14f3ae19"
API_KEYS = ["dc7bd0c8-0e85-4b94-af10-4a215bf7a831"]
REGISTER_KEY = "1234567890"


def register():
    new_uuid = str(uuid.uuid4())
    API_KEYS.append(new_uuid)
    with open('keys', 'w') as f:
        for item in API_KEYS:
            f.write(f"{item}\n")
    return new_uuid


def get_devices():
    files = os.listdir("./devices")
    print(files)
    return files


def udpate_device(content):
    if content['devicetype'] == "lock":
        result = update_lock(content)
    elif content['devicetype'] == "camera":
        result = update_camera(content)
    else: 
        result = "Invalid device type"
    return result


def update_lock(content):
    try:
        valid_statuses = ["locked", "unlocked"]
        if content['status'] not in valid_statuses:
            return "Invalid status requested"

        with open(f"./devices/{content['deviceid']}", 'r') as device_file:
            current_status = json.load(device_file)
            print(f"Current: {current_status}")
    
        result = "No action taken"
        if datetime.datetime.now() < datetime.datetime.strptime(content['timestamp'], "%Y-%m-%d %H:%M:%S.%f"):
            return "Invalid timestamp"
        if current_status['status'] == "locked":
            if content['status'] == "unlocked":
                print("Writing unlocked")
                with open(f"./devices/{content['deviceid']}", 'w') as device_file:
                    device_file.write('{"status" : "unlocked"}')
                result = "Lock successfully unlocked"
            else:
                result =  "Lock already locked"
        if current_status['status'] == "unlocked": 
            if content['status'] == "locked":
                print("Writing unlocked")
                with open(f"./devices/{content['deviceid']}", 'w') as device_file:
                    device_file.write('{"status" : "locked"}')
                result = "Lock successfully locked"
            else:
                result = "Lock already unlocked"
    except Exception as e:
        print(e)
        result = "Update Lock Exception"
    return result


def update_camera(content):
    try:
        valid_statuses = ["recording", "standby"]
        if content['status'] not in valid_statuses:
            return "Invalid status requested"
        
        with open(f"./devices/{content['deviceid']}", 'r') as device_file:
            current_status = json.load(device_file)
            print(f"Current: {current_status}")

        result = "No action taken"
        if datetime.datetime.now() < datetime.datetime.strptime(content['timestamp'], "%Y-%m-%d %H:%M:%S.%f"):
            return "Invalid timestamp"
        if not current_status['power']:
            if content['power']:
                print("Turning camera power on")
                current_status['power'] = True
                with open(f"./devices/{content['deviceid']}", 'w') as device_file:
                    json.dump(current_status, device_file)
                result = "Camera powered on"
        elif current_status['power']:
            if not content['power']:
                if current_status['status'] == "recording":
                    result = "Cannot power off camera while recording."
                else:
                    print("Turning camera power off")
                    current_status['power'] = False
                    with open(f"./devices/{content['deviceid']}", 'w') as device_file:
                        json.dump(current_status, device_file)
                    result = "Camera powered off"
            if content['power']:
                if content['status'] in valid_statuses:
                    print("Updating Camera Status")
                    current_status['status'] = content['status']
                    with open(f"./devices/{content['deviceid']}", 'w') as device_file:
                        json.dump(current_status, device_file)
                    result = f"Camera status updated to {content['status']}"
    except Exception as e:
        print(e)
        result = "Update Camera Exception"
    return result



class Message:
    def __init__(self, selector, sock, addr):
        self.selector = selector
        self.sock = sock
        self.addr = addr
        self._recv_buffer = b""
        self._send_buffer = b""
        self._jsonheader_len = None
        self.jsonheader = None
        self.request = None
        self.response_created = False
        self.authenticated = False

    def _set_selector_events_mask(self, mode):
        """Set selector to listen for events: mode is 'r', 'w', or 'rw'."""
        if mode == "r":
            events = selectors.EVENT_READ
        elif mode == "w":
            events = selectors.EVENT_WRITE
        elif mode == "rw":
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
        else:
            raise ValueError(f"Invalid events mask mode {repr(mode)}.")
        self.selector.modify(self.sock, events, data=self)

    def _read(self):
        try:
            # Should be ready to read
            data = self.sock.recv(4096)
        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            if data:
                self._recv_buffer += binascii.unhexlify(data)
            else:
                raise RuntimeError("Peer closed.")

    def _write(self):
        if self._send_buffer:
            print("sending", repr(self._send_buffer), "to", self.addr)
            try:
                # Should be ready to write
                sent = self.sock.send(binascii.hexlify(self._send_buffer))
            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass
            else:
                self._send_buffer = self._send_buffer[sent:]
                # Close when the buffer is drained. The response has been sent.
                if sent and not self._send_buffer:
                    self.close()

    def _json_encode(self, obj, encoding):
        return json.dumps(obj, ensure_ascii=False).encode(encoding)

    def _json_decode(self, json_bytes, encoding):
        tiow = io.TextIOWrapper(
            io.BytesIO(json_bytes), encoding=encoding, newline=""
        )
        obj = json.load(tiow)
        tiow.close()
        return obj

    def _create_message(
        self, *, content_bytes, content_type, content_encoding
    ):
        jsonheader = {
            "byteorder": sys.byteorder,
            "content-type": content_type,
            "content-encoding": content_encoding,
            "content-length": len(content_bytes),
        }
        jsonheader_bytes = self._json_encode(jsonheader, "utf-8")
        message_hdr = struct.pack(">H", len(jsonheader_bytes))
        message = message_hdr + jsonheader_bytes + content_bytes
        return message

    def _create_response_json_content(self):
        action = self.request.get("action")
        if not self.authenticated:
            if action == "register":
                if self.jsonheader['app-key'] == REGISTER_KEY:
                    content = {"result": register()}
                else:
                    content = {"result": "Invalid app key"}
            else:
                content = {"result":"Unauthenticated action attempted"}
        elif action == "get":
            content = {"result": get_devices()}

        elif action == "update":
            update = self.request.get("update")
            answer = udpate_device(update)
            content = {"result": answer}
    
        else:
            content = {"result": f'Error: invalid action "{action}".'}
        content_encoding = "utf-8"
        response = {
            "content_bytes": self._json_encode(content, content_encoding),
            "content_type": "text/json",
            "content_encoding": content_encoding,
        }
        return response

    def _create_response_binary_content(self):
        response = {
            "content_bytes": b"First 10 bytes of request: "
            + self.request[:10],
            "content_type": "binary/custom-server-binary-type",
            "content_encoding": "binary",
        }
        return response

    def process_events(self, mask):
        if mask & selectors.EVENT_READ:
            self.read()
        if mask & selectors.EVENT_WRITE:
            self.write()

    def read(self):
        self._read()

        if self._jsonheader_len is None:
            self.process_protoheader()

        if self._jsonheader_len is not None:
            if self.jsonheader is None:
                self.process_jsonheader()

        if self.jsonheader:
            if self.request is None:
                self.process_request()

    def write(self):
        if self.request:
            if not self.response_created:
                self.create_response()

        self._write()

    def close(self):
        print("closing connection to", self.addr)
        try:
            self.selector.unregister(self.sock)
        except Exception as e:
            print(
                "error: selector.unregister() exception for",
                f"{self.addr}: {repr(e)}",
            )

        try:
            self.sock.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f"{self.addr}: {repr(e)}",
            )
        finally:
            # Delete reference to socket object for garbage collection
            self.sock = None

    def process_protoheader(self):
        hdrlen = 2
        if len(self._recv_buffer) >= hdrlen:
            self._jsonheader_len = struct.unpack(
                ">H", self._recv_buffer[:hdrlen]
            )[0]
            self._recv_buffer = self._recv_buffer[hdrlen:]

    def process_jsonheader(self):
        hdrlen = self._jsonheader_len
        if len(self._recv_buffer) >= hdrlen:
            self.jsonheader = self._json_decode(
                self._recv_buffer[:hdrlen], "utf-8"
            )
            self._recv_buffer = self._recv_buffer[hdrlen:]
            for reqhdr in (
                "byteorder",
                "content-length",
                "content-type",
                "content-encoding",
                "app-key",
            ):
                if reqhdr not in self.jsonheader:
                    raise ValueError(f'Missing required header "{reqhdr}".')

    def process_request(self):
        content_len = self.jsonheader["content-length"]
        if not len(self._recv_buffer) >= content_len:
            return
        data = self._recv_buffer[:content_len]
        self._recv_buffer = self._recv_buffer[content_len:]
        if self.jsonheader["app-key"] in API_KEYS:
            self.authenticated = True
        if self.jsonheader["content-type"] == "text/json":
            encoding = self.jsonheader["content-encoding"]
            self.request = self._json_decode(data, encoding)
            print("received request", repr(self.request), "from", self.addr)
        else:
            # Binary or unknown content-type
            self.request = data
            print(
                f'received {self.jsonheader["content-type"]} request from',
                self.addr,
            )
        # Set selector to listen for write events, we're done reading.
        self._set_selector_events_mask("w")

    def create_response(self):
        if self.jsonheader["content-type"] == "text/json":
            response = self._create_response_json_content()
        else:
            # Binary or unknown content-type
            response = self._create_response_binary_content()
        message = self._create_message(**response)
        self.response_created = True
        self._send_buffer += message

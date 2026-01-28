#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import paramiko, json, sys, subprocess, socket


def phase1(data):
    results = dict()
    conn = data['conn']['p1']
    cur_pwd = conn['pwd'][0]
    ## Initiate SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ### Grading check 2 occurs during initialization of SSH connection. Will determine current password of `user`
    try:
        ssh.connect(conn['hn'][0],username=conn['un'],password=cur_pwd,timeout=10)
    except paramiko.AuthenticationException:
        try:
            cur_pwd = conn['pwd'][1]
            ssh.connect(conn['hn'][0],username=conn['un'],password=cur_pwd,timeout=10)
        except paramiko.AuthenticationException:
            #print("ERROR:\t Cannot connect with expected credentials `tartans` or `tartans1`. Please check guide")
            results['GradingCheck1'] = "Failure -- Unable to authenticate with expected passwords. Please check 'user' password and try again."
            results['GradingCheck2'] = "Failure -- Unable to authenticate with expected passwords. Please check 'user' password and try again."
            results['GradingCheck3'] = "Failure -- Unable to authenticate with expected passwords. Please check 'user' password and try again."
            return results
        except Exception as e:
            results['GradingCheck1'] = "Failure -- Exception occurring during SSH connection"
            results['GradingCheck2'] = "Failure -- Exception occurring during SSH connection"
            results['GradingCheck3'] = "Failure -- Exception occurring during SSH connection"
            return results
        else:
            results['GradingCheck2'] = "Failure -- Password for VNC has not been updated."
    else:
        results['GradingCheck2'] = "Failure -- Local user 'user' password has not been updated."

    for k, tasks in data['phase1'].items():
        if "Check1" in k:
            cmd = tasks['1'][1].format(cur_pwd)
            exp_resp = tasks['1'][2]
            try:
                stdin, stdout, stderr = ssh.exec_command(cmd,timeout=3)
                resp1 = stdout.read().decode().strip().split()
            except Exception as e:
                results['GradingCheck1'] = "Failure -- Exception occurred during SSH connection to remote host. Please check network and try again."
            else:
                parse_stdout = resp1
                while '' in parse_stdout:
                    parse_stdout.remove("")
                    
                ## Check that all required configs in `common-password` file have been added
                policy_chk = all(item in parse_stdout for item in exp_resp)
                if policy_chk:
                #if parse_stdout == resp:
                    results['GradingCheck1'] = "Success -- Password Policy has been updated correctly."
                else:
                    results['GradingCheck1'] = "Failure -- Password policy has not been updated correctly."
        elif "Check2" in k:
            if 'Password for VNC' in results['GradingCheck2']:
                cmd = tasks['1'][1]
                resp = tasks['1'][2]
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd,timeout=3)
                    resp2 = stdout.read().decode().strip()
                except Exception as e:
                    results['GradingCheck2'] = "Failure -- Exception occurred during SSH connection to remote host. Please check network and try again."
                else:
                    cur_hash = resp2
                    if resp in cur_hash:
                        results['GradingCheck2'] = "Success -- Passwords have been updated for 'user' and VNC."
        else:   # grading check 3 
            for num,cmds in tasks.items():
                if num == '1':
                    try:
                        stdin, stdout, stderr = ssh.exec_command(cmds[1],timeout=3)
                        resp3 = stdout.read().decode()
                    except Exception as e:
                        results['GradingCheck3'] = "Failure -- Exception occurred during SSH connection to remote host. Please check network and try again."
                        break
                    if cmds[2] in resp3:
                        results['GradingCheck3'] = "Failure -- HMI page not reachable from hmi-admin-console."
                    else:
                        results['GradingCheck3'] = "Failure -- HMI Pump not reachable."
                        break
                elif num == '2':
                    ssh.close()
                    try:
                        ssh.connect(conn['hn'][1],username=conn['un'],password=conn['pwd'][0],timeout=10)
                    except paramiko.AuthenticationException:
                        results['GradingCheck3'] = "Failure -- Unable to authenticate and login to hmi-admin-console."
                        break
                    try:
                        stdin, stdout, stderr = ssh.exec_command(cmds[1],timeout=3)
                        resp4 = stdout.read().decode()
                    except Exception as e:
                        results['GradingCheck3'] = "Failure -- Exception occurred during SSH connection to remote host. Please check network and try again."
                        break
                    if cmds[2] in resp4:
                        results['GradingCheck3'] = "Failure -- Firewall is misconfigured or disabled."
                else:
                    try:
                        stdin, stdout, stderr = ssh.exec_command(cmds[1],timeout=3)
                        resp5 = stdout.read().decode()
                        #print(resp5)
                    except socket.timeout as e :
                        results['GradingCheck3'] = "Success -- Firewall rules has been implemented correctly."
                    except paramiko.SSHException as e:
                        results['GradingCheck3'] = "Failure -- SSH Exception occurred during grading. Please check host and try again."
                    except Exception as e:
                        results['GradingCheck3'] = "Failure -- Exception occurred during SSH connection to remote host. Please check network and try again."
                    
                        
    ssh.close()
    return results


def phase2(data):
    org_ip = data['phase2']['GradingCheck4']['1'][1]
    new_ip = data['phase2']['GradingCheck4']['2'][1]
    org_resp = data['phase2']['GradingCheck4']['1'][2]
    new_resp = data['phase2']['GradingCheck4']['2'][2]
    resp1 = subprocess.run(org_ip,shell=True,capture_output=True).stdout.decode('utf-8')
    resp2 = subprocess.run(new_ip,shell=True,capture_output=True).stdout.decode('utf-8')
    
    results = dict()
    if new_resp in resp1:
        results['GradingCheck4'] = "Failure -- Application server still located at the IP 10.4.4.3."
    elif org_resp in resp2:
        results['GradingCheck4'] = "Failure -- Application server cannot be hit at the new IP 10.3.3.3."
    elif new_resp in resp2:
        results['GradingCheck4'] = "Success -- Application Server can be reached at the new IP 10.3.3.3."
    else:
        results['GradingCheck4'] = "Failure -- Unknown issue occurred during grading."
    return results
    

def phase3(data):
    results = dict()
    ssh_info = data['conn']['p3']
    cur_data = data['phase3']['GradingCheck5']
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ### Grading check 2 occurs during initialization of SSH connection. Will determine current password of `user`
    try:
        ssh.connect(ssh_info['hn'][0],username=ssh_info['un'],password=ssh_info['pwd'][0],timeout=10)
    except paramiko.AuthenticationException:
        results['GradingCheck5'] = "Failure -- Unable to authenticate during SSH connection to HMI-Server."
    except Exception as e:
        results['GradingCheck5'] = f"Failure -- Exception occurred during SSH attempt: {e}"
        
    ## NEED TO FINALIZE ONCE ACCEPTED CONFIG IS DETERMINED
    for num, cmd in cur_data.items():
        if num == "1":
            try:
                stdin, stdout, stderr = ssh.exec_command(cmd[1],timeout=3)
                resp1 = stdout.read().decode()
            except Exception as e:
                results['GradingCheck5'] = "Failure -- Exception occurred during SSH connection to remote host. Please check network and try again."
                break
            if cmd[2] in resp1:
                results['GradingCheck5'] = "Failure -- HMI not reachable from hmi-admin-console."
            else:
                results['GradingCheck5'] = "Failure -- HMI not reachable from hmi-server."
        else:
            ssh.close()
            try:
                ssh.connect(ssh_info['hn'][1],username=ssh_info['un'],password=ssh_info['pwd'][1],timeout=10)
            except paramiko.AuthenticationException:
                results['GradingCheck5'] = "Failure -- Unable to authenticate during SSH connection to hmi-admin-console."
            except Exception as e:
                results['GradingCheck5'] = f"Failure -- Exception occurred during SSH attempt to hmi-admin-console: {e}"
            stdin, stdout, stderr = ssh.exec_command(cmd[1],timeout=3)
            resp2 = stdout.read().decode()
            if cmd[2] in resp2:
                results['GradingCheck5'] = "Success -- Firewall rules have been configured correctly."
            else:
                results['GradingCheck5'] = "Failure -- HMI not reachable from hmi-admin-console."
    ssh.close()
    return results


def mini_lab(data):
    results = dict()
    for k, tasks in data['mini_lab'].items():
        if 'Check6' in k:
            c6 = data['mini_lab']['GradingCheck6']['1']
            resp = subprocess.run(c6[1],shell=True,capture_output=True).stdout.decode('utf-8')
            if c6[2] in resp:
                results['GradingCheck6'] = "Success -- hmi-remote-client system has been moved to the user network."
            else:
                results['GradingCheck6'] = "Failure -- hmi-remote-client system cannot be reached in the user network."
        else:
            conn = data['conn']['ml']
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ### Grading check 2 occurs during initialization of SSH connection. Will determine current password of `user`
            try:
                ssh.connect(conn['hn'][0],username=conn['un'],password=conn['pwd'][0],timeout=10)
            except paramiko.AuthenticationException:
                results['GradingCheck7'] = "Failure -- Unable to authenticate during SSH connection to HMI-Server."
                break
            except Exception as e:
                results['GradingCheck7'] = f"Failure -- Exception occurred during SSH attempt to 10.4.4.250: {e}"
                break
                
            try:
                stdin, stdout, stderr = ssh.exec_command(tasks['1'][1],timeout=3)
                resp1 = stdout.read().decode()
            except Exception as e:
                results['GradingCheck7'] = "Failure -- Exception occurred during SSH connection to remote host. Please check network and try again."
                break
            if tasks['1'][2] in resp1:
                results['GradingCheck7'] = "Success -- Firewall rules have been configured correctly."
            else:
                results['GradingCheck7'] = "Failure -- VNC connection to 10.4.4.250:5903 failed."
                                
    ssh.close()
    return results



if __name__ == '__main__':
    data = {
        "conn": {
            "p1":{
                "hn":['10.4.4.250', '10.4.4.51'],
                "un":"user",
                "pwd":['tartans','tartans1']
            },
            "p2":{},
            "p3":{
                "hn":["10.4.4.250",'10.4.4.51'],
                "un":"user",
                "pwd":["tartans1","tartans"]
            },
            "ml":{
                "hn":["10.1.1.151"],
                "un":"user",
                "pwd":["tartans"]
            }
        },
        "phase1": {
            "GradingCheck1": {
                ## Checking that the password policy was updated on hmi-server
                "1": ["pwd_policy", 'echo "{}" | sudo -S bash -c "sed -n \"25p\" /etc/pam.d/common-password"', ['password', 'requisite', 'pam_pwquality.so', 'retry=3', 'maxrepeat=3', 'minlen=8']]

            },
            "GradingCheck2": {
                ## Checking that the password for 'user' and 'vnc' has both been updated to 'tartans1'
                "1":["vnc_pwd_change2",'md5sum /home/user/.vnc/passwd | awk "{ print $1 }"','e1ad1d73d6f6b57e08733e50eb19e1d0']
            },
            "GradingCheck3":{
                "1":["srvr_to_pump",'curl 10.4.4.251:5000/','{"1":'],  # Need to test when rules are implemented to know what to parse for. Alternate cmd: `ufw status numbered`
                "2":["admin_to_hmi",'echo "close" | telnet 10.4.4.250 5902', "Connected to 10.4.4.250"],
                "3":['port_chk','nc -zvw3 10.4.4.250 22','timed out']
            }
        },
        "phase2": {
            "GradingCheck4": {
                "1": ["move_app_srvr1","ping -c 1 10.4.4.3"," 100% packet loss"],
                "2": ["move_app_srvr2", "ping -c 1 10.3.3.3"," 0% packet loss"],
                # Possible alternate grading, checking `arp` logs OR doing `nslookup 10.3.3.3:8080`. TBD
            }
        },
        "phase3": {
            "GradingCheck5": {
                "1":["hmi_srv_to_hmi",'curl http://10.3.3.3:8080/','Water Sensors'],           # TBD, need to test & view expected output & parse string
                "2":["admin_to_hmi",'curl http://10.3.3.3:8080/','Water Sensors']
                #"3":["ping_tst","ping -c 1 10.4.4.251","100% packet loss"]
            }
        },
        "mini_lab": {
            "GradingCheck6": {
                "1":["move_remote_host", "ping -c 1 10.1.1.151", " 0% packet loss"]    
            },
            "GradingCheck7": {
                "1":["remote_to_vnc",'echo "close" | telnet 10.4.4.250 5903', "Connected to 10.4.4.250"]           # TBD, need to test & view expected output & parse string
            }
            
        }
    }
    args = sys.argv[1:]
    if len(args) > 0:
        passed_phase = args[-1].strip().lower()
        if passed_phase in data.keys():
            #print(f"Starting grading of {args[-1]} questions")
            res = globals()[passed_phase](data)
            for key,val in res.items():
                print(key, ' : ', val)
        else:
            # This section is intended to be used if 'phases' are not enabled in server & all grading occurs at once
            ...
    else:
        ...

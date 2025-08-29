#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import paramiko, sys, subprocess, json

def phase1(data):
    results = dict()
    conn = data['conn']['p1']
    info = data['phase1']

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(conn['hn'][0],username=conn['un'],password=conn['pwd'],timeout=10)
    except paramiko.AuthenticationException:
        results['GradingCheck1'] = "Failure -- Unable to authenticate with expected credentials."
        results['GradingCheck2'] = "Failure -- Unable to authenticate with expected credentials."
        return results
    for key,value in info.items():
        if "Check1" in key:
            for num, cmds in value.items():
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmds[1], timeout=10)
                    resp = [
                        stdout.read().decode().strip(),
                        stderr.read().decode().strip()           
                        ]
                    
                except Exception as e:
                    results[key] = f'Failure -- Exception occurred sending command. Exception:\n{str(e)}'
                    break
                if cmds[2] not in resp[0]:
                    results[key] = f"Failure -- Malicious Ad not found in blacklist"
                    break
                if num == "2":
                    results[key] = "Success -- Malicious Ad has been blacklisted."
            ssh.close()
        elif "Check2" in key:
            for num,cmds in value.items():
                res = subprocess.run(cmds[1],shell=True,capture_output=True)
                resp = [
                    res.stdout.decode().lower().split('\n'),
                    res.stderr.decode().strip()
                ]
                if resp[0] == []:
                    results[key] == "Failure -- Did not receive response from DNS request."
                elif '' in resp[0]:
                    while '' in resp[0]:
                        resp[0].remove('')
                out_chk = resp[0][-1].replace(' ','')
                if cmds[2] not in out_chk:
                    results[key] = "Failure -- Blacklist has not been configured correctly"
                    continue
                results[key] = "Success -- Blacklist has been configured correctly" 
    try:
        ssh.close()
    except:
        ...
    return results


def phase2(data):
    results = dict()
    conn = data['conn']['p2']
    info = data['phase2']
    resp = list()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(conn['hn'][0],username=conn['un'],password=conn['pwd'],timeout=10)
    except paramiko.AuthenticationException:
        results['GradingCheck3'] = "Failure -- Unable to authenticate with expected credentials."
        ssh.close()
        return results

    try:
        stdin, stdout,stderr = ssh.exec_command(info['GradingCheck3']['1'][1], timeout=10)
        resp = [
            stdout.read().decode().lower().split('\n'),
            stderr.read().decode().strip()
        ]
    except Exception as e:
        results['GradingCheck3'] = f"Failure -- Exception occurred processing command. Exception:\n{str(e)}"
        return results
    finally:
        ssh.close()

    # check output of `mail.log` to see if badguy@baddomain.com has been blocked
    found_badguy = False
    found_unknown = False
    
    for line in list(reversed(resp[0])):
        # Check for badguy@baddomain.com record
        if all(item in line for item in info['GradingCheck3']['1'][2]):
            found_badguy = True
            
        # Check for unknown client record
        if all(item in line for item in info['GradingCheck3']['1'][3]):
            found_unknown = True
            
        # If both conditions are met, we can break early
        if found_badguy and found_unknown:
            results['GradingCheck3'] = "Success -- Domain blacklisting has been configured correctly"
            return results
    
    res = list()
    res.append("Mail originating from the domain 'baddomain.com' have not been denied.") if not found_badguy else None
    res.append("Mail originating from the IP '123.45.67.202' have not been denied") if not found_unknown else None
    
    try:
        output = '\n'.join(res) if len(res) == 2 else res[0]
        results['GradingCheck3'] = "Failure -- " + output
    except Exception as e:
        # Error likely relates to trying to index item in list that doesnt exist. Check parsing logic to determine error
        results['GradingCheck3'] = f"Failure -- Exception occurred processing command. Exception:\n{str(e)}"
    finally:
        return results


def phase3(data):
    results = dict()
    info = data['phase3']

    try:
        resp = subprocess.run(info['GradingCheck4']['1'][1],shell=True,capture_output=True,timeout=10)
        resp = [
            resp.stdout.decode().split('\n'),
            resp.stderr.decode().strip()
        ]
    except Exception as e:
        results['GradingCheck4'] = f"Failure -- Exception occurred processing command. Exception:\n{str(e)}"
        return results


    if resp[0] == []:
        results['GradingCheck4'] = "Failure -- DNS over TLS has not been configured correctly and is not returning expected results."
        return results
    #elif resp[1] != '':
    #    results['GradingCheck4'] = f"Failure -- Error occurred . Exception:\n{resp[1]}"
    #    return results

    for line in resp[0]:
        line = line.strip()
        if line.startswith(';') or line == '':
            continue
        if all(item in line for item in info['GradingCheck4']['1'][2]):
            results['GradingCheck4'] = "Success -- DNS over TLS has been configured correctly"
            return results
    results['GradingCheck4'] = "Failure -- DNS over TLS has not been configured correctly"
    return results


def mini_lab(data):
    results = dict()
    info = data['mini_lab']
    
    for key, val in info.items():
        if "Check5" in key:
            gv = val['gv']
            blocked = list()

            for sender in gv:
                cmd = info['GradingCheck5']['1'][1]
                cmd = cmd.replace('-s', f'-s {sender}')
                resp = list()
                out = subprocess.run(cmd,shell=True,capture_output=True)
                resp = [
                    out.stdout.decode('utf-8').lower(),
                    out.stderr.decode('utf-8')
                ]
                if all(item in resp[0] for item in info['GradingCheck5']['1'][2]):
                    cur_domain = sender.split('@',1)[1]
                    blocked.append(cur_domain)
            if len(blocked) != 2:
                results['GradingCheck5'] = "Failure -- Domain blacklist has not been configured correctly."
            else:
                results['GradingCheck5'] = "Success -- Domain blacklist has been configured correctly."
        else:
            gv = val['gv']
            blocked = list()
            for sender in gv:
                cur_domain = sender.split('@',1)[1]
                cmd = info['GradingCheck6']['1'][1].format(cur_domain)
                resp = list()
                out = subprocess.run(cmd,shell=True,capture_output=True)
                resp = [
                    out.stdout.decode().lower().split('\n'),
                    out.stderr.decode('utf-8')
                ]
                
                if resp[0] == []:
                    results[key] == "Failure -- Did not receive response from DNS request."
                    return results
                while '' in resp[0]:
                    resp[0].remove('')
                if 'servfail' in resp[0][-1]:
                    results[key] = "Failure -- Malicious domains have not been blocked correctly."
                    return results
                out_chk = resp[0][3].replace(' ','')
                if info['GradingCheck6']['1'][2] in out_chk:
                    blocked.append(cur_domain)
            if len(blocked) != 2:
                results['GradingCheck6'] = 'Failure -- traffic is not being blocked correctly..'
            else:
                results['GradingCheck6'] = "Success -- traffic has been blocked correctly."
    return results


if __name__ == '__main__':
    gv = [
        subprocess.run(f"vmware-rpctool 'info-get guestinfo.sender2_1'",shell=True,capture_output=True).stdout.decode('utf-8').strip(),
        subprocess.run(f"vmware-rpctool 'info-get guestinfo.sender2_2'",shell=True,capture_output=True).stdout.decode('utf-8').strip()
        ]
    data = {
        "conn": {
            "p1":{
                "hn":['10.3.3.10', "10.1.1.50"],
                "un":"user",
                "pwd":'tartans'
            },
            "p2":{
                "hn":["10.3.3.11"],
                "un":"user",
                "pwd":"tartans"
            },
            "ml":{
                "hn":[],
                "un":"user",
                "pwd":"tartans"
            }
        },
        "phase1": {
            "GradingCheck1": {
                ## Checking that ad has been blacklisted
                "1": ["blacklist1", 'echo "tartans" | sudo -S bash -c "pihole -b -l | grep www.malicious-ad.com"', "www.malicious-ad.com"],
                "2": ["blacklist2", 'echo "tartans" | sudo -S bash -c "cat /var/log/pihole.log | grep malicious"', "blacklisted"]
            },
            "GradingCheck2": {
                ## Check that blacklisted site returns correct resp.
                "1":["ad_lookup1",'nslookup www.malicious-ad.com 10.3.3.10','address:10.3.3.15']
                #"2":["ad_lookup2",'echo "tartans" | sudo -S bash -c "curl http://malicious-ad.com"','warning']
            }
        },
        "phase2": {
            "GradingCheck3":{
                # Check that intended domains are denied
                "1":["deny_chk1", 'echo "tartans" | sudo -S bash -c "cat /var/log/mail.log"', ['baddomain.com','sender address rejected', 'access denied'], ['123.45.67.202', 'client host rejected','access denied']]
            }
        },
       "phase3": {
            "GradingCheck4":{
                # Check that DNS is configured correctly.
                "1":["dns_tls", 'dig \@10.0.0.1 -p 853 +tls www.malicious-ad.com', ['www.malicious-ad.com.', '3600','IN', 'A', '123.45.67.201']]
            }
        },
        "mini_lab": {
            "GradingCheck5": {
                "gv": gv,
                "1":["chk_mail", 'python3 /home/user/skillsHub/custom_scripts/send_mail.py -s -r jsmith@lab.net -p 25 -S 10.3.3.11 -c \'{"subject":"Malicious Message","body":"This is the message"}\' -n 1', ['client host rejected', 'access denied']]
            },
            "GradingCheck6": {
                "gv":gv,
                "1":['chk_pi', 'nslookup {} 10.3.3.10', 'address:0.0.0.0']
            }
            
        }
    }
    args = sys.argv[1:]
    if len(args) > 0:
        passed_phase = args[-1].strip().lower()
        if passed_phase in data.keys():
            #print(f"Starting grading of {args[-1]} questions")
            res = globals()[passed_phase](data)
            #print(json.dumps(res,indent=2))
            for key,val in res.items():
                print(key, ' : ', val)
        else:
            # This section is intended to be used if 'phases' are not enabled in server & all grading occurs at once
            ...
    else:
        ...

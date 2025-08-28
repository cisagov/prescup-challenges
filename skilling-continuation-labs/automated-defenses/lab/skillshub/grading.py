#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import paramiko, json, sys, subprocess, os, time

#####
# NOTE:
# Please read the `grading_README.md` file to get explanation of how the Skills Hub handles grading 
# and requirements needed in your script.
#####

def runSSHCommand(username=None, password=None, hostname=None, cmdList=None):
    if any(arg is None for arg in [username,password,hostname,cmdList]):
        print("on call is missing an argument. Ensure that values are passed for the username, password, hostname, and cmdList")
        return {"error":"Function call missing arguments."}
    elif type(cmdList) != list:
        print("The commands you want to run should be passed in as a list variable regardless of the number of them")
        return {"error": "Commands passed are not correct data type"}
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, username=username, password=password, timeout=10)
    except paramiko.Exception as e:
        ssh.close()
        return {"error": f"Exception occurred while attempting SSH connection. Message: {str(e)}","passed args": f"username: {username}, pwd: {password}, hostname: {hostname}, commands: {cmdList}"}

    results = dict()
    for index,cmd in enumerate(cmdList):
        try:
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=5)
            results[f'cmd{index}'] = {
                "commandExecute":cmd,
                "stdout":stdout.read().decode().strip(),
                "stderr":stderr.read().decode().strip()
            }
        except Exception as e:
            results[f"cmd{index}"] = {
                "commandExecute":cmd,
                "stdout":"",
                "stderr":f"Error occurred during command execution.\error msg:\t{str(e)}"
            }
    ssh.close()
    return results



def phase1(sub=None):
    results = dict()
    check1_state_file = "check1_state_file.txt"

    def run_ssh_command(command):
        process = subprocess.run(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process.stdout.strip()

    # GradingCheck1 with four SSH commands
    if os.path.exists(check1_state_file):
        results['GradingCheck1'] = "Success -- Successfully mount the backup network share to the Documents directory."

    else:
        try:
            # Check if network share is mounted
            ssh_command1_1 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no user@10.1.1.51 \"mount | grep '/srv/nfs/backups'\""
            output1_1 = run_ssh_command(ssh_command1_1)
            if "10.5.5.5:/srv/nfs/backups" not in output1_1:
                results['GradingCheck1'] = "Failure -- Please ensure the backup share is properly mounted at /mnt/backup."
                return results

            # Checks if backup files are accessible from the share
            ssh_command1_2 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no user@10.1.1.51 \"ls /mnt/backup | grep -E 'textfile1|textfile2|textfile3|imagefile1.jpg|imagefile2.jpg|imagefile3.jpg' | wc -l\""
            output1_2 = run_ssh_command(ssh_command1_2)
            if "6" not in output1_2:
                results['GradingCheck1'] = "Failure -- Please ensure the backup share is properly mounted at /mnt/backup."
                return results

            # Checks if files were copied to the Documents directory
            ssh_command1_3 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no user@10.1.1.51 \"ls /home/user/Documents | grep -E 'textfile1|textfile2|textfile3|imagefile1.jpg|imagefile2.jpg|imagefile3.jpg' | wc -l\""
            output1_3 = run_ssh_command(ssh_command1_3)
            if "6" not in output1_3:
                results['GradingCheck1'] = "Failure -- Please ensure the six(6) text and image files are copied to the Documents directory."
                return results

            # Checks if restoration script has executable flag
            #ssh_command1_4 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no user@10.1.1.51 \"ls -l /home/user/restore_data.sh | grep  'x'\""
            #output1_4 = run_ssh_command(ssh_command1_4)
            #if "-rwx" not in output1_4:
            #    results['GradingCheck1'] = "Failure -- Please ensure you have added the executable flag to the restore_data.sh file."
            #    return results

            results['GradingCheck1'] = "Success -- Successfully mount the backup network share to the Documents directory."

            with open(check1_state_file, "w") as f:
                f.write("GradingCheck1 Completed")

        except Exception as e:
            results['GradingCheck1'] = f"Failure -- Exception: {str(e)}"
            return results

    # GradingCheck2
    try:
        # Sub-check 1: Retrieve good hashes
        ssh_command2_1 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no user@10.1.1.51 \"for file in /home/user/Documents/*; do [ -f \"\$file\" ] && md5sum \"\$file\"; done\""
        with open("goodhashes.txt", "w") as goodhashes:
            subprocess.run(ssh_command2_1, stdout=goodhashes, stderr=subprocess.PIPE, shell=True, text=True, timeout=10)

        # Sub-check 2: Verify good hashes
        local_command2_1 = "less goodhashes.txt | grep -E 'b6c1540a1ef6b7f9c276701e6f277c1c|073da8f0a53248b4a822835f9b9475b3|cbc8f0f68964d04e91509ec5e25bfdfa|aca63a8b00ec3032e478d78a13ddc29b|4db976b8578d71ee74710e48ad01dc35|040c7700fed2faad4c0ecb75c67ec57c' | wc -l"
        result = subprocess.run(local_command2_1, shell=True, text=True, stdout=subprocess.PIPE)

        # Extract the line count from the output
        line_count = int(result.stdout.strip())

        if line_count != 6:
            results['GradingCheck2'] = "Failure -- Please ensure the six(6) text and image files were properly restored to the Documents directory rerun the restore_data.sh script manually if needed."
            return results  # Exit on failure

        # Sub-check 3: Retrieve bad hashes
        ssh_command2_2 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no user@10.1.1.51 \"for file in /home/user/bad/*; do [ -f \"\$file\" ] && md5sum \"\$file\"; done\""
        with open("badhashes.txt", "w") as badhashes:
            subprocess.run(ssh_command2_2, stdout=badhashes, stderr=subprocess.PIPE, shell=True, text=True, timeout=10)
        
        # Sub-check 4: Verify bad hashes
        local_command2_2 = "less badhashes.txt | grep -E 'dc9faad5a9f8a5c6b683422d4d54b0d3|8cce794c4441481858d199c86cb1a57f|0718e58ae0e30582265d591ad26cd55d' | wc -l"
        result = subprocess.run(local_command2_2, shell=True, text=True, stdout=subprocess.PIPE)

        # Extract the line count from the output
        line_count = int(result.stdout.strip())

        if line_count != 3:
            results['GradingCheck2'] = "Failure -- Please ensure the encrypted files were copied to the 'bad'. You can rerun the restore_data.sh script manually if needed."
            return results  # Exit on failure

        results['GradingCheck2'] = "Success -- Successfully restored encrypted data."
    
    except Exception as e:
        results['GradingCheck2'] = f"Failure -- Exception: {str(e)}"
        return results

    return results

def phase2(sub=None):
    results = dict()

    #Grading Check 3
    check3_state_file = "check3_state_file.txt"

    def run_ssh_command(command):
        process = subprocess.run(command, shell=True, capture_output=True)
        os.system(f"echo {process.stdout.decode('utf-8')} > /home/user/Desktop/stdout")
        os.system(f"echo {process.stderr.decode('utf-8')} > /home/user/Desktop/stderr")
        return process.stdout.decode('utf-8').strip()

    if os.path.exists(check3_state_file):
        results['GradingCheck3'] = "Success -- Successfully implemented throttling and queue management."

    else:
        try:
            # Gets the rule ID for the Rate Limiter
            #ssh_command3_1 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no admin@10.0.0.1 /bin/sh -c \"'less /tmp/rules.debug | grep Rate'\""
            #ssh_command3_1 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no admin@10.0.0.1 'less /tmp/rules.debug | grep Rate'"
            output3_1 = runSSHCommand('admin','tartans','10.0.0.1',['cat /tmp/rules.debug | grep hrottle'])
            resp3_1 = output3_1['cmd0']['stdout']
            #print(resp3_1)
            if "hrottle" not in resp3_1:
                results['GradingCheck3'] = "Failure -- Please ensure the throttle rule has been added to the WAN interface."
                return results
            else:
                outputList = resp3_1.split()
                lastEntry = outputList[-1].strip('"')
                id_number = lastEntry.split(':',1)[1]

            # Checks for the existence of that rule ID in the filter logs, which means that rule was triggered.
            #ssh_command3_2 = f"sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no admin@10.0.0.1 /bin/sh -c \"'less /var/log/filter.log | grep {id_number}'\""
            #output3_2 = run_ssh_command(ssh_command3_2)
            output3_2 = runSSHCommand('admin','tartans','10.0.0.1',[f"less /var/log/filter.log | grep {id_number}"])
            resp3_2 = output3_2['cmd0']['stdout']
            if "123.45.67.201" not in resp3_2:
                results['GradingCheck3'] = "Failure -- The firewall logs did not show that the HTTP traffic was throttled. Please ensure the limiter settings are correct and that the limiter is applied to the Throttle for HTTP rule."
                return results

            # Checks the config file for the traffic shaper looking for the tags that tell if HTTP and SMTP have the correct priority values; no real way to check for it actually occurring though without seeing firewall states live.
            #ssh_command3_3 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no admin@10.0.0.1 \"cat /cf/conf/config.xml | grep -E '<smtp>L</smtp>|<http>H</http>' | wc -l\""
            output3_3 = runSSHCommand('admin','tartans','10.0.0.1',["cat /cf/conf/config.xml | grep -E '<smtp>L</smtp>|<http>H</http>' | wc -l"])
            resp3_3 = output3_3['cmd0']['stdout']
            #output3_3 = run_ssh_command(ssh_command3_3)
            if "2" not in resp3_3:
                results['GradingCheck3'] = "Failure -- Please ensure that the http protocol has been given a higher priority, while the smtp protocol is given a lower priority in the traffic shaper wizard."
                return results

            results['GradingCheck3'] = "Success -- Throttling and Queue Management Settings and Rules Were Implemented Correctly."

            with open(check3_state_file, "w") as f:
                f.write("GradingCheck3 Completed")

        except Exception as e:
            results['GradingCheck3'] = f"Failure -- Exception: {str(e)}"
            return results
    
    #GradingCheck4
    try:
        # Check if host was blocked by Suricata
        ssh_command4_2 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no admin@10.0.0.1 /bin/sh -c \"'pfctl -t snort2c -T show'\""
        output4_2 = run_ssh_command(ssh_command4_2)
        if "123.45.67.201" not in output4_2:
            results['GradingCheck4'] = "Failure -- Please ensure the SYN flood has been blocked by Suricata and try again."
            return results

        results['GradingCheck4'] = "Success -- Suricata Rules Have Blocked SYN Flood Attempts."
    
    except Exception as e:
        results['GradingCheck4'] = f"Failure -- Exception: {str(e)}"
        return results

    return results


def mini_lab(sub=None):
    results = dict()
    #check5_state_file = "check5_state_file.txt"

    #def run_ssh_command(command):
    #    process = subprocess.run(command, shell=True, capture_output=True)
    #    os.system(f"echo {process.stdout.decode('utf-8')} > /home/user/Desktop/stdout")
    #    os.system(f"echo {process.stderr.decode('utf-8')} > /home/user/Desktop/stderr")
    #    return process.stdout.decode('utf-8').strip()

    index = subprocess.run(f"vmware-rpctool 'info-get guestinfo.index'",shell=True,capture_output=True).stdout.decode('utf-8').strip()

    # Execute the traffic script based on the index value for the gamespace
    MC_SCRIPT = f"/home/user/s05/mini{index}.sh"
    DOS_SCRIPT = f"/home/user/s05/dos.sh"

    #GradingCheck5
    #if os.path.exists(check5_state_file):
    #    results['GradingCheck5'] = "Success -- Successfully blocked the RST flood with a Suricata rule."
    #else:
    #    try:
    #        # Check if host was blocked by Suricata
    #        subprocess.run(['bash',DOS_SCRIPT], check=True)
    #        #time.sleep(10)
    #        ssh_command5_1 = "sshpass -p 'tartans' ssh -o StrictHostKeyChecking=no -b 10.5.5.5 admin@10.0.0.1 /bin/sh -c \"'pfctl -t snort2c -T show'\""
    #        output5_1 = run_ssh_command(ssh_command5_1)
    #        blocked_ips = {"123.45.67.221", "123.45.67.222", "123.45.67.223", "123.45.67.224"}
    #        if any(ip in output5_1 for ip in blocked_ips):
    #            results['GradingCheck5'] = "Success -- Successfully blocked the RST flood with a Suricata rule."
    #            with open(check5_state_file, "w") as f:
    #                f.write("GradingCheck5 Completed")
    #        else:
    #            results['GradingCheck5'] = "Failure -- Please ensure the RST flood has been blocked by Suricata and try again."
    #
    #    except Exception as e:
    #        results['GradingCheck5'] = f"Failure -- Exception: {str(e)}"

    try:
        subprocess.run(['bash', MC_SCRIPT], check=True)
    except Exception as e:
        print(f"Failed to run external script: {e}")

    try:
        subprocess.run(['bash', DOS_SCRIPT], check=True)
    except Exception as e:
        print(f"Failed to run external script: {e}")

    results['Mini-Challenge'] = "Success -- Traffic is now complete. You should see logs and alerts in the honeypot dashboards and a new IP in the Suricata block list if the rule was added correctly. Feel free to run the traffic again as needed."
    return results

if __name__ == '__main__':
    phases = ['phase1','phase2','mini_lab']
    args = sys.argv[1:]
    if len(args) > 0:
        passed_phase = args[-1].strip().lower()
        if passed_phase in phases:
            ## This code will execute IF phases is enabled & current phase was passed to script.
            args.pop(-1)
            if len(args) != 0:
                ## This code executes if user submitted answer & it was passed to grading script. 
                submissions = json.loads(args[0])
                res = globals()[passed_phase](submissions)
            else:
                # This code executes if no submission made from user
                res = globals()[passed_phase]()
                
            for key,val in res.items():
                print(key, ' : ', val)
        else:
            # This code will execute if phases are disabled BUT there is still a submission from the user. For this example, we will execute all the functions above. 
            submissions = json.loads(args[0])
            res = dict()
            for phase in phases:    
                res.update(globals()[phase](submissions))
                
            for key,val in res.items():
                print(key, ' : ', val)
    else:
        ## This code will execute if no args were passed, which means that phases are disabled & no submissions occur from user
        res = dict()
        for phase in phases:
            res.update(globals()[phase]())

        for key,val in res.items():
                print(key, ' : ', val)




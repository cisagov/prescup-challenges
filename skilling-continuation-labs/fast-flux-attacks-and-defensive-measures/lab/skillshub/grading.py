#!/usr/bin/env python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import paramiko, json, sys, subprocess, os, requests

#####
# NOTE:
# Please read the `grading_README.md` file to get explanation of how the Skills Hub handles grading and requirements needed in your script.
# `sub` variable in each function represents data that was submitted and was passed from server to this script
#   - Could include filename, text entered, multiple choice option chosen, etc.
#####

## This function can be used to run SSH command against remote host and should return any/all relavent information from execution
def runSSHCommand(username=None, password=None, hostname=None, cmdList=None):
    if any(arg is None for arg in [username,password,hostname,cmdList]):
        #print("Error: Function call is missing an argument. Ensure that values are passed for the username, password, hostname, and cmdList")
        return {"error":"Function call missing arguments."}
    elif type(cmdList) != list:
        #print("Error: The commands you want to run should be passed in as a list variable regardless of the number of them")
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


## NOTE: This function has not been fully tested and may contain bugs
def execute_in_docker(file_name=None, docker_image=None, libs=False, lib_folder=None):
    if any(arg is None for arg in [file_name, docker_image]):
        #print("Error: Function call is missing an argument. Ensure that values are passed for the file_name and container")
        return {"error":"Function call missing file path."}
    if ((libs) and (lib_folder == None)) or ((not libs) and (lib_folder != None)):
        #print("Error: Either `libs` is True AND `lib_folder` is None OR `libs` is False and lib_folder is pointing to directory.")
        return {"error":"Variable libs and lib_folder mismatch"}

    if not os.path.isfile(file_path):
        #print("File passed does not exist or is incorrect.")
        return {"error":"File passed missing or incorrect"}

    docker_command = list()
    file_path = f"/home/user/skillsHub/uploaded_files/{file_name}"
    if libs:
        lib_dir = f"/home/user/skillsHub/docker_libs/{lib_folder}"
        if not os.path.isdir(lib_dir):
            #print("lib_folder value passed does not exist or is incorrect.")
            return {"error":"Lib directory does not exist."}

        ## This may need editing depending on if order of libs being installed matters
        lib_list = os.path.listdir(lib_dir)   
        pip_install_cmd = "pip3 install " + " ".join(lib_list)

        docker_command = [
            "docker", "run", "--rm", "--net=none",              # Was in original command, unsure needed:   "--memory=128m", "--cpus=0.5",
            "-v", f"{file_path}:/app/{file_name}",
            "-v", f"{lib_dir}:/app/libs",
            docker_image, "bash", "-c",
            f"{pip_install_cmd} && python3 /app/{file_name}"
        ]
    else:
        docker_command = [
            "sudo", "docker", "run", "--rm", "--net=none",                  
            "-v", f"{os.path.abspath(file_name)}:/app/{file_name}",
            docker_image, "python3", f"/app/{file_name}"
        ]
    
    try:
        output = subprocess.run(docker_command, capture_output=True, timeout=10)
        results[f'cmd'] = {
            "stdout":output.read().decode().strip(),
            "stderr":output.read().decode().strip()
        }
        return results
    except subprocess.TimeoutExpired:
        #print("Execution time out")
        return {"error":f"docker command timed out"}
    except Exception as e:
        #print(f"Unknown exception occurred: {str(e)}")
        return {"error":f"Exception occurred: {str(e)}"}

def phase1(sub=None):
    results = dict()
    download_path = os.path.expanduser("/home/user/Downloads/malicious.exe")

    # Try to download the file
    try:
        response = requests.get('http://phished.mal.ware', allow_redirects=True, timeout=30)

        # Check if the request is successful and it's a downloadable file
        if response.status_code == 200:
            # Save the file to the expected download location
            with open(download_path, 'wb') as file:
                file.write(response.content)
            
            # Check if the file was saved correctly
            if os.path.exists(download_path):
                results['GradingCheck1'] = "Success -- malicious.exe was downloaded"
            else:
                results['GradingCheck1'] = "Failure -- File not saved as malicious.exe"
        else:
            results['GradingCheck1'] = f"Failure -- Unexpected status code: {response.status_code}"

    except Exception as e:
        results['GradingCheck1'] = f"Failure -- Could not access URL: {e}"

    return results

def phase2(sub=None):
    results = dict()

    try:
        out1 = subprocess.check_output(['nslookup', 'phish3d.mal.ware', '10.3.3.10'], text=True)
        out2 = subprocess.check_output(['nslookup', 'testing.com', '10.3.3.10'], text=True)
        out3 = subprocess.check_output(['nslookup', 'legit.safe.org', '10.3.3.10'], text=True)

        if 'Address: 0.0.0.0' not in out1:
            results['GradingCheck2'] = "Failure -- Lookups for phish3d.mal.ware are still allowed."
        elif 'Address: 0.0.0.0' not in out2:
            results['GradingCheck2'] = "Failure -- Lookups for testing.com are still allowed. As this site was not added to the exception list, it should also be blocked."
        elif 'Address: 123.45.67.20' not in out3:
            results['GradingCheck2'] = "Failure -- Lookups for legit.safe.org were blocked."
        else:
            results['GradingCheck2'] = "Success -- You have blocked the malicious sites and allowed the safe site."
    except Exception as e:
        results['GradingCheck2'] = f"Failure -- DNS check error: {e}"

    return results


    

def phase3(sub=None):
    results = dict()
    results['GradingCheck3'] = "Failure"
    return results


if __name__ == '__main__':
    # phases variable should contain list of all phases implemented in the lab & has a function declared above
    phases = ['phase1','phase2','phase3']
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

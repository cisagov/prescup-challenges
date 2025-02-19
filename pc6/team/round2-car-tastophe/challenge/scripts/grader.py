#!/usr/bin/python

import json
import logging
import paramiko

server = "twig-api.merch.codes"
username = "user"
password = "D0Th3C4nC4n!?"

success = True

logging.basicConfig(
    filename='/var/log/challengeGrader/gradingCheck.log', 
    level=logging.INFO, 
    format='%(asctime)s %(levelname)s %(message)s')

def gradeCan(ssh):
    try: 
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('cat /home/user/ac_status.json')

        output = ssh_stdout.read().decode()
        error = ssh_stderr.read().decode()
    except Exception as e:
        success = False
        logging.error(f"Error reading ac_status.json -- {e}")
        print("GradingCheckMechanicSignal: Mechanic reports A/V shows climate control off")
        print("GradingCheckBrakes: No (or an insignificant number of) bad brake pressure readings discovered.")
        return
    finally:
        ssh.close()
        del ssh_stdin, ssh_stdout, ssh_stderr

    logging.info(f"ac_status.json output - {output}")

    if error != "":
        success = False
        logging.error(f"Error retrieving ac_status.json -- {error}")
        print("GradingCheckMechanicSignal: Mechanic reports A/V shows climate control off")
        print("GradingCheckBrakes: No (or an insignificant number of) bad brake pressure readings discovered.")
        return

    try:
        data = json.loads(output)
        if not data["on"] or data["power"] <= 0:
            logging.info(f"Climate control reported as off or not powered ({data['on']} {data['power']:x})")
            print("GradingCheckMechanicSignal: Mechanic reports A/V shows climate control off")
        elif data["displayOn1"] != 0x78 or data["displayOn2"] != 0x88:
            logging.info(f"Climate control reported as on but display is off ({data['displayOn1']:x} {data['displayOn2']:x})")
            print("GradingCheckMechanicSignal: Mechanic reports A/V eyebrow shows climate control on, but no display")      
        elif data["userFanSpeed"] != 0xff:
            logging.info(f"Climate control reports incorrect fan speed ({data['userFanSpeed']:x})")
            print("GradingCheckMechanicSignal: Mechanic reports A/V shows incorrect fan speed")    
        else:
            logging.info(f"GradingCheckMechanicSignal: Success -- The mechanic was signalled to begin removing the device")
            print("GradingCheckMechanicSignal: Success -- The mechanic was signalled to begin removing the device")

        if data["brakesHalted"]:
            logging.info("GradingCheckBrakes: Success -- The VCM believes the brakes are faulty, and is no longer accelerating.")
            print("GradingCheckBrakes: Success -- The VCM believes the brakes are faulty, and is no longer accelerating.")
        else:
            logging.info(f"Brakes not reported as faulty - check canServer logs on twig-api for more info")
            print("GradingCheckBrakes: No (or an insignificant number of) bad brake pressure readings discovered.")
        
    except Exception as e:
        success = False
        logging.error(f"Error reading ac_status.json - {e}")
        print("GradingCheckMechanicSignal: Mechanic reports A/V shows climate control off")
        print("GradingCheckBrakes: No (or an insignificant number of) bad brake pressure readings discovered.")
        return

def gradeWeb(ssh):
    # Curl from inside server so it isn't intercepted by pfSense
    try: 
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('curl -sS "http://twig-api.merch.codes/twig/gdc/RemoteACRecordsRequest?DCIM=&VIN=R0MHBBXF3P5069X37&RegionCode=US"')

        output = ssh_stdout.read().decode()
        error = ssh_stderr.read().decode()
    except Exception as e:
        success = False
        logging.error(f"Error reading web server -- {e}")
        print("GradingCheckBatteryDrain: Battery not draining")
        return
    finally:
        del ssh_stdin, ssh_stdout, ssh_stderr

    logging.info(f"Web server AC output - {output}")

    if error != "":
        success = False
        logging.error(f"Web server AC error -- {error}")
        print("GradingCheckBatteryDrain: Battery not draining")
        return

    try:
        data = json.loads(output)
        result = data["RemoteACRecords"]["RemoteACOperation"]
        if result == "START":
            print("GradingCheckBatteryDrain: Success -- The AC drained the battery over night, and the target called our mechanic")
        else:
            print("GradingCheckBatteryDrain: Battery not draining")
    except Exception as e:
        success = False
        logging.error(f"Error reading json -- {e}")
        print("GradingCheckBatteryDrain: Battery not draining")
        return

if __name__ == "__main__":
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
    try: 
        ssh.connect(server, username=username, password=password)
        gradeWeb(ssh)
        gradeCan(ssh)
    except Exception as e:
        logging.error(f"Error connecting to canbus server -- {e}")
        if not success:
            exit(-1)
    finally:
        ssh.close()

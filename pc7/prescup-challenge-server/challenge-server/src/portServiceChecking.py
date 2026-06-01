import subprocess, logging, re, socket, requests, ipaddress
from datetime import datetime
from time import sleep
from pythonping import ping

logger = logging.getLogger("challengeServer")


def checkLocalPorts():
    '''
    Runs a subprocess to list open TCP and UDP ports
    Returns Stdout from the subprocess
    '''
    stdout = subprocess.run(f"ss -nltup", shell=True, capture_output=True).stdout.decode("UTF-8")
    return stdout


def checkLocalPortLoop(interval=30):
    '''
    Checks open ports forever in a loop. Default time between checks is 30s. 
    Logs results to the same logger as the rest of the ChallengeServer (in one line)
    Logs in a more readable format written to /var/log/open-ports
    '''

    logger.info(f"Checking local open ports every {interval} seconds")
    lastRead = ""
    while True:
        date = datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
        open_ports = checkLocalPorts()
        stripped = re.sub(r"\s+", " ", open_ports).replace("\n", "\\n") # removing multiple spaces in a row and newline chars make this nicer for syslog (one line logging)
        if stripped != lastRead:
            logger.info(f"Open ports: {stripped}")
            lastRead = stripped
            with open("/var/log/open-ports", "a") as f:
                f.write(f"""
########
{date}
{open_ports}""")
        sleep(interval)


def isIPv4(host):
    '''
    Checks the IP version of a given address
    Returns True if the address is IPv4
    Returns False if the address is IPv6
    If host is a hostname/FQDN, attempts to resolve as IPv4
    If unsuccessful, assumes address is IPv6 
    '''
    if isValidIPv4(host):
        logger.info(f"Regex matched {host} as a valid IPv4 address")
        return True
    elif isValidIPv6(host):
        logger.info(f"Regex matched {host} as a valid IPv6 address")
        return False
    # If it is not IPv4 or IPv6 here, then we have a FQDN or Hostname and attempt to resolve  
    else:
        try:
            ipAddr = socket.gethostbyname(str(host))    
            logger.info(f"Resolved IPv4 address is {ipAddr}")
            return True
        except socket.gaierror as e:
            errNum = e.errno
            if errNum == int(-5):
                logger.info(f"Treating {host} as an IPv6 address")
                return False
            elif errNum == int(-3):
                logger.error(f"Failed to resolve {host} - Check DNS Entry. Assuming IPv4 in the meantime")
                return True
            else:
                logger.error(f"Socket Error in isIPv4 Function - {e}. Assuming IPv4 in the meantime")
                return True
        except Exception as e:
            logger.error(f"Exception in isIPv4 Function - {e}. Assuming IPv4 in the meantime") 
            return True


def isValidIPv4(host):
    '''
    A regular expression to check if a given host
    value matches the pattern of an IPv4 address. 
    Returns True if address matches the pattern
    Returns False if it does not
    ''' 
    ipv4_re = re.compile(
    (r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.)'
     r'{3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'))
    return bool(ipv4_re.match(host))


def isValidIPv6(host):
    '''
    A regular expression to check if a given host 
    value matches the pattern of an IPv6 address. 
    Returns True if address matches the pattern 
    Returns False if it does not
    '''
    ipv6_re = re.compile(
    (r'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,7}:|'
    r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
    r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
    r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
    r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
    r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
    r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
    r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
    r'::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|'
    r'(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|'
    r'(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
    r'([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|'
    r'(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|'
    r'(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'))
    return bool(ipv6_re.match(host))


def checkPing(host, count=1):
    '''
    Checks to see if a host is able to be reached via ping
    Returns True if the host can be pinged
    Returns False if the host cannot be pinged
    '''
    logger.info(f"Pinging host {host}")
    try:
        results = subprocess.run(f"ping {host} -W 1 -c {count}", shell=True, capture_output=True)
        exit_code = results.returncode
        stdout_string = " \\n ".join(line.strip() for line in str(results.stdout.decode("UTF-8")).splitlines())
        stderr_string = " \\n ".join(line.strip() for line in str(results.stderr.decode("UTF-8")).splitlines())
        logger.info(f"Exit code {exit_code} from pinging {host}")
        if exit_code == 0:
            logger.info(f"Successful ping to host {host} - {stdout_string}")
            return True
        logger.error(f"Failed to ping host {host} - {stderr_string}")
        return False
    except Exception as e:
        logger.error(f"Failed to ping host {host}. Got exception {str(e)}")
        return False


def checkSocket(host, port):
    '''
    Checks to see if a remote socket (host/port pair) is reachable
    Returns True if socket connection is successful (port is reachable)
    Returns False if socket connection failed (port is not reachable)
    '''
    logger.info(f"Attempting to connect to socket {host}:{port}")
    success = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) if isIPv4(host) else socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, int(port)))
        s.shutdown(socket.SHUT_RDWR)
        logger.info(f"Successful connection to socket {host}:{port}")
        success = True 
    except socket.gaierror as e:
        logger.error(f"Failed connection to socket {host}:{port}. Get Address Info (DNS) error prevented socket connection. Exception: {e}")
    except TimeoutError as e:
        logger.error(f"Failed connection to socket {host}:{port}. Connection timeout.")
    except Exception as e:
        logger.error(f"Failed connection to connect to socket {host}:{port}. Exception {e}")
    finally:
        s.close()
    return success


def checkWeb(host, port=80, path='/'):
    '''
    Checks connection to a web URL
    Returns True if the web request returns a 200
    Returns False if the web request returns anything but a 200
    If host is an IP address, IP version is checked as IPv6 requires [ ] brackets 
    '''
    fqdn = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?$)')
    if fqdn.search(host): # Check if host is FQDN. If True, IP version does not matter 
        url = f"http://{host}:{port}{path}"
        logger.info("checkWeb is using FQDN")
    elif isIPv4(host) == True: 
        url = f"http://{host}:{port}{path}"
        logger.info("checkWeb is using IPv4")
    else:
        url = f"http://[{host}]:{port}{path}" 
        logger.info("checkWeb is using IPv6")
    logger.info(f"Attempting to reach {url}")
    try:
        result = requests.get(url=url)
        logger.info(f"Web request returned {result.status_code}: {result.content}")
        return result.status_code == 200
    except requests.exceptions.Timeout as e:
        logger.error(f"Failed connection to {url}. Connection Timeout Exception: {e}")
    except requests.exceptions.InvalidURL as e:
        logger.error(f"Failed connection to {url}. Invalid URL Exception: {e}")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Failed connection to {url}. Connection Error: {e}")
    except Exception as e:
        logger.error(f"Failed connection to {url}. Got Exception: {e}")
    return False


def checkService(service:dict):
    '''
    Checks to see if the service is available once. 
    Returns True is the service is reachable. 
    Returns False is the service is unreachable. 
    '''

    logger.info(f"Checking availability of service: {service}")
    reachable = False
    service_type = service['type']
    if service_type == 'ping':
        reachable = checkPing(service['host'])
    elif service_type =='socket':
        reachable = checkSocket(service['host'],service['port'])
    elif service_type == 'web':
        reachable = checkWeb(service['host'], service['port'], service['path'])
    
    if reachable:
        logger.info(f"Service available: {service}")
        return True
    else:
        logger.error(f"Service unavailable: {service}")
        return False


def waitForService(service:dict, interval=2, max_attempts=None):
    '''
    Checks the service in a loop until it becomes available or max_attempts is reached. 
    Returns once the service is available or max_attempts is reached.
    Default time between checks is 2s.
    '''

    service_available = False
    attempts = 0
    while True:
        attempts += 1
        logger.info(f"Waiting for service to become available (attempt number {attempts}): {service}")
        service_available = checkService(service)
        if service_available:
            return service_available
        if max_attempts and attempts == max_attempts:
            logger.error(f"Service unavailable after max attempts ({attempts}): {service}")
            return False
        sleep(interval)


def checkServiceLoop(service:dict, interval=30, max_checks=None):
    '''
    Checks the availability of the service forever in a loop (or until max_checks is reached). Default time between checks is 30s. 
    '''

    logger.info(f"Checking service {service} every {interval} seconds")
    attempts = 0
    while True:
        attempts += 1
        logger.info(f"Service check number {attempts} for {service}")
        checkService(service)
        if max_checks and attempts == max_checks:
            logger.info(f"Reached the maximum number of service checks ({max_checks}).. Will no longer check on service {service}.")
            return True
        sleep(interval)

        
#!/usr/bin/python3

from flask import Flask, render_template, jsonify, send_from_directory
from flask_executor import Executor
import subprocess, logging, yaml, datetime, os


FILE_DIRECTORY = "/home/user/gradingServer/hosted_files"

# configure logging
logging.basicConfig(format='%(asctime)s  %(levelname)s  %(message)s', level=logging.INFO, datefmt='%m/%d/%Y %I:%M:%S %p')


# define the flask application
app = Flask(__name__)
executor = Executor(app)
task = None
submit_time = 'Never"'

@app.route('/', methods=['GET'])
def home():
    # renders the home page
       return render_template('index.html')

@app.route('/grade')
def grade():
    global task
    global submit_time
    if not task:
        submit_time = datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")
        logging.info(f"Submitting a grading task at {submit_time}")
        task = executor.submit(do_grade)
        return render_template('grading.html', submit_time=submit_time)
    if task.done():
        results, tokens = task.result()
        task = None
        return render_template('graded.html', results=results, tokens=tokens, submit_time=submit_time)
    if task.running():
        logging.info("Task is still running")
        return render_template('grading.html', submit_time=submit_time)

def do_grade():
    '''
    This method is the actual grading and token reading. 
    The method gets called from the Jinja template rendering (inside { } in the graded.html file)
    '''

    # run the grading script and parse output into a dict
    ## The output variable has properties output.stdout  and  output.stderr
    output = subprocess.run(f"./{conf['gradingScript']}", capture_output=True)
    out_string =  output.stdout.decode('utf-8')
    results = []
    for sub in out_string.split('\n'):
        if ':' in sub:
            results.append(map(str.strip, sub.split(':', 1)))

    results = dict(results)

    # for each result that is returned, check if success is in the message. 
    # If success is in the message, then read and store the token for that check
    tokens = {}
    for key, value in results.items():
        if "success" in value.lower():
            tokens[key] = read_token(key)
        else:
            tokens[key] = "You did not earn a token for this part"

    # results, tokens = future.result()
    logging.info(f"Server sees {conf['gradingScript']} results as: {results}")
    logging.info(f"Server sees tokens as: {tokens}")
    return results, tokens

def read_token(part_name):
    '''
    Function reads tokens from files. 
    Assumes files are in the standard Kali Iso location and that tokens are only 1 line long

    This method takes a Check name as an argument. Examples can be "Check1", "Check2", etc.
    These names come from your GradingScript (The keys in the json blob)
    '''

    try:
        value = conf['grading']['parts'][part_name]
    except KeyError:
        logging.error(f"There is no match for {part_name} in the config file. Valid part names from config file are: {conf['grading']['parts'].keys()}")
        return "Unexpected error encountered. Contact an administrator."
    
    if conf['grading']['tokenLocation'].lower() == 'guestinfo':
        try: 
            output = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.{value}'", shell=True, capture_output=True)
            if 'no value' in output.stderr.decode('urf-8'):
                logging.error(f"No value found when querying guestinfo variables for guestinfo.{value}")
                return "Unexpected error encountered. Contact an administrator."
            return output.stdout.decode('utf-8')
        except:
            logging.error("Error when trying to get token from guestinfo vars")
            return "Unexpected error encountered. Contact an administrator."
    else:
        try:
            with open(value, 'r') as f:
                return f.readline()
        except:
            logging.error(f"Error opening file {value} when trying to read token for check {part_name}")
            return "Unexpected error encountered. Contact an administrator."



@app.route("/files")
def list_files():
    """Endpoint to list files on the server."""
    files = {}
    for filename in os.listdir(FILE_DIRECTORY):
        path = os.path.join(FILE_DIRECTORY, filename)
        if os.path.isfile(path):
            files[filename] = path
    
    return render_template('files.html', files=files)


@app.route("/files/<path:path>")
def get_file(path):
    """Download a file."""
    return send_from_directory(FILE_DIRECTORY, path, as_attachment=True)



# The line below allows the do_grade method to be called from inside the Jinja html template 
# app.jinja_env.globals['do_grade'] = do_grade

# serve this app on port 80
if __name__ == '__main__':
    # parse config file
    with open('config.yml', 'r') as config_file:
        try:
            conf = yaml.safe_load(config_file)
        except yaml.YAMLError:
            logging.error("Error Reading YAML in config file")
            exit(1)
    
    # exit if server is not enabled
    if not conf['enabled']:
        logging.info("Grading Server is not enabled. Exiting")
        exit(0)
    
    # server is enabled, read grading script variable and start server
    logging.info(f"Starting the grading server website. The grading script is {conf['gradingScript']}")
    app.run(host='0.0.0.0', port=80, debug=False)

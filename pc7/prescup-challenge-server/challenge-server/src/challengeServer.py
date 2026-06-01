#!/usr/bin/python3


import random
import sys
from flask import Flask, jsonify, render_template, send_file, send_from_directory, request, redirect, abort
from flask.helpers import url_for
from flask_executor import Executor
from concurrent.futures import ThreadPoolExecutor
import logging, datetime, os, threading, subprocess

# local imports
from gradingFunctions import do_grade, done_grading, run_and_log
from portServiceChecking import checkLocalPortLoop, waitForService, checkServiceLoop
import cronGrading, globals


# Initialize before starting up
globals.init()

# configure logging (default log level of INFO)
logging.basicConfig(
    format='%(asctime)s | %(threadName)s | %(levelname)s | %(message)s',
    level=logging.INFO
)
logger = logging.getLogger("challengeServer")

# Silence the logging of requests, too verbose
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# logger.info("Challenge Server Operating in a Workspace" if globals.in_workspace else "Challenge Server Operating in a Gamespace")

# define the flask application
app = Flask(__name__)
app.url_map.strict_slashes = False

executor = Executor(app)
executor.add_default_done_callback(done_grading)

task = None

server_ready = False


@app.route('/', methods=['GET'])
def home():

    mode = globals.grading_mode

    # There is no grading, so redirect to the hosted files
    if not globals.grading_enabled:
        if globals.hosted_files_enabled:
            return redirect(url_for("list_files"))
        else: 
            return "<p>All challenge website features disabled. If grading is required for this challenge, please refer to challenge description for grading instructions.</p>"

    if not server_ready:
        logger.info(f"Tried to access site before server was marked as ready.")
        return "<p>Challenge is starting up. Try again in a bit to see if the challenge is ready.</p>"

    ## This means grading is enabled
    ### We need to decide which page to show
    if mode == 'button':
       return render_template('button.html')
    if mode == 'text':
        return render_template('text.html', parts=globals.grading_parts)
    if mode == 'text_single':
        # get the dictionary of just the first part in the config and pass that to the text template
        part = {list(globals.grading_parts)[0]:globals.grading_parts[list(globals.grading_parts)[0]]}
        return render_template('text.html', parts=part)
    if mode == 'cron':
        logger.warning("I have not tested cron grading! Use at your own risk")
        return render_template('cron.html', results=globals.results, tokens=globals.tokens, parts=globals.grading_parts, 
            submit_time=globals.submit_time, limit=globals.cron_limit, interval=globals.cron_interval)


@app.route('/grade', methods=['post', 'get'])
def grade():
    '''
    This method gets called when a user requests grading (presses grade/submit button)
    The method will create the grading task and render the 'grading page' if the task is still running
    When grading is done, the 'graded page' will be rendered. 
    '''

    if not globals.grading_enabled:
        return render_template('no_grading.html')

    if not server_ready:
        logger.info(f"Tried to access site before server was marked as ready.")
        return "<p>Challenge is starting up. Try again in a bit to see if the challenge is ready.</p>"

    global task

    # if there is no current grading task, then create one
    if not task:
        now_time = datetime.datetime.now()
        now_string = now_time.strftime("%m/%d/%Y %H:%M:%S")
        submit_time_time = datetime.datetime.strptime(globals.submit_time, "%m/%d/%Y %H:%M:%S")

        # rate limiting grading attempts - display graded and let user know how long to wait
        if submit_time_time + globals.grading_rateLimit > now_time:
            try_again = (globals.grading_rateLimit - (now_time - submit_time_time)).total_seconds().__int__()
            logger.info(f"Hit rate limit. Telling user to try again in {try_again} seconds")
            return render_template("graded.html",  results=globals.results, tokens=globals.tokens, parts=globals.grading_parts, submit_time=globals.submit_time, try_again=try_again)
        
        globals.submit_time = now_string
        logger.info(f"Submitting a grading task at {globals.submit_time}")
        if request.method == "GET":
            # GET requests should call do_grade without any arguments
            task = executor.submit(do_grade)
        if request.method == "POST":
            # POST requests will several form fields to pass to the grading script
            # Arguments to do_grade are the values from the form fields submitted
            task = executor.submit(do_grade, *request.form.to_dict().values())

        return render_template('grading.html', submit_time=globals.submit_time)

    # if the current grading task is done, collect and display the results
    # the task is then nulled out
    if task.done():
        # globals.results, globals.tokens = task.result()
        task = None
        if globals.submission_method == 'display':
            logger.info(f"Rendering graded results html page for user. Fatal error is {globals.fatal_error}")
            return render_template('graded.html', results=globals.results, tokens=globals.tokens, parts=globals.grading_parts, submit_time=globals.submit_time, fatal_error=globals.fatal_error)
        else:
            return render_template("auto_submit.html", submit_time=globals.submit_time)
    
    # if the current grading task is still running, show the grading page with the last submit time
    if task.running():
        logger.info("Grading task is still running")
        return render_template('grading.html', submit_time=globals.submit_time)


def get_file_list():
    files = {}
    for filename in os.listdir(globals.hosted_file_directory):
        path = os.path.join(globals.hosted_file_directory, filename)
        if os.path.isfile(path) and filename[0] != '.':
            files[filename] = path
    return files

@app.route("/files", )
def list_files():
    """Endpoint to list files on the server."""
    if globals.hosted_files_enabled:
        if not server_ready:
            logger.info(f"Tried to access site before server was marked as ready.")
            return "<p>Challenge is starting up. Try again in a bit to see if the challenge is ready.</p>"
        return render_template('files.html', files=get_file_list())
    return render_template('no_files.html')


@app.route("/files/<path:path>")
def get_file(path):
    """Download a file."""
    if globals.hosted_files_enabled:
        if not server_ready:
            logger.info(f"Tried to access site before server was marked as ready.")
            return "<p>Challenge is starting up. Try again in a bit to see if the challenge is ready.</p>"
        if path in get_file_list():
            logger.info(f"User is downloading file {path}")
            return send_from_directory(globals.hosted_file_directory, path, as_attachment=True)
        else:
            abort(404)
    return render_template('no_files.html')

WALLPAPER_FILENAME = "wallpaper.png"
WALLPAPER_ROOT = "/app/wallpapers"

def _get_year() -> int:
    # Env var name requested: pc_year
    v = os.getenv("pc_year", "").strip()
    if not v.isdigit():
        raise ValueError("pc_year not an int")
    year = int(v)
    if year < 1 or year > 10:
        raise ValueError("pc_year out of range")
    return year

def _get_challenge_name() -> str:
    name = os.getenv("challenge_name", "").strip()
    if not name:
        raise ValueError("challenge_name missing")
    return name

def _wallpaper_abs_path(year: int) -> str:
    # /app/wallpapers/pc{year}/*.png  (pick one at random)
    year_dir = os.path.join(WALLPAPER_ROOT, f"pc{year}")

    if not os.path.isdir(year_dir):
        raise ValueError("year directory missing")

    pngs = [
        os.path.join(year_dir, f)
        for f in os.listdir(year_dir)
        if f.lower().endswith(".png") and os.path.isfile(os.path.join(year_dir, f))
    ]

    if not pngs:
        raise ValueError("no png files found")

    return random.choice(pngs)

_wallpaper_missing_logged = False
@app.get("/wallpaper")
def wallpaper_meta():
    # Temporarily allow this old route, should be deprecated
    return challenge_meta()

@app.get("/challenge")
def challenge_meta():
    global _wallpaper_missing_logged
    try:
        challenge_name = _get_challenge_name()
        year = _get_year()
        try: 
            path = _wallpaper_abs_path(year)
            if not os.path.isfile(path):
                logger.error(f"Could not find file at {path}")
                return jsonify({"challenge_name": challenge_name, "wallpaper": "NONE", "wallpaper_year": year})
            return jsonify({"challenge_name": challenge_name, "wallpaper": WALLPAPER_FILENAME, "wallpaper_year": year})
        except ValueError as e:
            if not _wallpaper_missing_logged:
                logger.info("Wallpaper not found, returning NONE")
                _wallpaper_missing_logged = True
            return jsonify({"challenge_name": challenge_name, "wallpaper": "NONE", "wallpaper_year": year})
    except Exception:
        logger.exception("wallpaper_meta failed")
        abort(404)

@app.get(f"/{WALLPAPER_FILENAME}")
def wallpaper_file():
    try:
        _get_challenge_name()
        year = _get_year()
        path = _wallpaper_abs_path(year)
        if not os.path.isfile(path):
            logger.error(f"Could not find file at {path}")
            abort(404)
        return send_file(path)
    except Exception:
        logger.exception("wallpaper_file failed")
        abort(404)

def start_grading_server():
    # exit if server is not enabled
    if not globals.conf['grading']['enabled'] and not globals.conf['hosted_files']['enabled']:
        logger.info("Website features not enabled. Will serve disabled page from /.")
    
    else:
        logger.info(f"Starting grading server website with grading mode {globals.grading_mode}")
        # if using the cron mode, we need to set the config variables and start/schedule the grading thread
        if globals.grading_mode == 'cron':
            cronGrading.set_cron_vars()
            logger.info(f"Waiting {globals.cron_delay} seconds until executing cron-style grading")
            cron_thread = threading.Timer(globals.cron_delay, cronGrading.run_cron_thread)
            cron_thread.start()

    # Log that the server is starting up and start server on port 80
    logger.info(f"Starting the challenge server website.")
    app.run(host='0.0.0.0', port=int(os.getenv('CHALLENGE_PORT', '80')), debug=False)


def run_startup_scripts():
    successes = {}
    errors = {}
    if not globals.startup_scripts:
        logger.info("There are no startup scripts to run")
        return successes, errors
    
    # if not globals.startup_workspace and globals.in_workspace:
    #     logger.info("Startup scripts are disabled when running in a workspace. Skipping startup scripts")
    #     return successes, errors

    for startup_script in globals.startup_scripts:
        logger.info(f"Calling {startup_script}")
    
        # run the startup script and parse output into a dict
        ## The output variable has properties output.stdout  and  output.stderr
        try:
            output, _ = run_and_log([f"{globals.custom_script_dir}/{startup_script}"], "startup")
            successes[startup_script] = output
        # Something happened if there was a non-zero exit status. Log this and set fatal_error
        except subprocess.CalledProcessError as e:
            logger.error(f"Startup script {startup_script} returned with non-zero exit status {e.returncode}.")
            errors[startup_script] = f"stdout: {e.stdout}\tstderr: {e.stderr}"
    return successes, errors

if __name__ == '__main__':

    # Read the configuration
    logger.info(f"Challenge server starting up")
    globals.read_config()

    # start the website
    grading_server_thread = threading.Thread(target=start_grading_server, name="GradingServer")
    grading_server_thread.start()

    # wait for blocking services to come up
    logger.info(f"Waiting for blocking services to become available")
    globals.blocking_threadpool.map(waitForService, globals.blocking_services)
    globals.blocking_threadpool.shutdown(wait=True)
    logger.info(f"All blocking services are available")

    # run startup scripts
    successes, errors = run_startup_scripts()
    if errors:
        logger.error(f"Startup scripts exited with error(s): {list(errors.keys())}")
        exit(1)
    if successes: 
        logger.info(f"All startup scripts exited normally: {list(successes.keys())}")

    server_ready = True # mark server as ready after startup scripts finish

    # run a thread that will periodically check on all required services
    service_check_pool = ThreadPoolExecutor(thread_name_prefix="ServiceCheck")
    service_check_pool.map(checkServiceLoop, globals.required_services)

    # run a thread that will periodically list the local open ports 
    port_checker_thread = threading.Thread(target=checkLocalPortLoop, name="LocalPortChecker")
    
    port_checker_thread.start()
    grading_server_thread.join()

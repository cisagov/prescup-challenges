import os
from time import sleep
from gradingFunctions import do_grade
import logging, subprocess, datetime
import globals

logger = logging.getLogger("challengeServer")

def set_cron_vars():
    '''
    This is going to set the value of the cron global vars
    First try to see if there are any test guestinfo variables set
    If there are test guestinfo variables set, then use those
    If there are no test guestinfo variables set, then use the config file or defaults
    '''
    global cron_at

    cron_interval_cmd = os.getenv("test_cron_interval")
    if cron_interval_cmd is None:
        globals.cron_interval = globals.conf['grading']['cron_interval'] if globals.conf['grading']['cron_interval'] else 60
    else:
        globals.cron_interval = int(cron_interval_cmd)
        logger.info(f"Using a guestinfo var intended for testing: cron_interval = {globals.cron_interval}")

    cron_limit_cmd = os.getenv("test_cron_limit")
    if cron_limit_cmd is None:
        globals.cron_limit = globals.conf['grading']['cron_limit'] if globals.conf['grading']['cron_limit'] else -1
    else:
        globals.cron_limit = int(cron_limit_cmd)
        logger.info(f"Using a guestinfo var intended for testing: cron_limit = {globals.cron_limit}")

    cron_delay_cmd = os.getenv("test_cron_delay")
    if cron_delay_cmd is None:
        globals.cron_delay = globals.conf['grading']['cron_delay'] if globals.conf['grading']['cron_delay'] else 0
    else:
        globals.cron_delay = int(cron_delay_cmd)  
        logger.info(f"Using a guestinfo var intended for testing: cron_delay = {globals.cron_delay}")

    cron_at_cmd = os.getenv("test_cron_at")
    if cron_at_cmd is None:
        globals.cron_at = globals.conf['grading']['cron_at']
    else:
        globals.cron_at = cron_at_cmd.strip()
        logger.info(f"Using a guestinfo var intended for testing: cron_at = {globals.cron_at}")

    # calculates the total delay by using the cron_at setting and adding it to the cron_delay
    if globals.cron_at is not None:
        time = globals.cron_at.split(':')
        current_time = datetime.datetime.now()

        start_time = datetime.datetime(current_time.year, current_time.month, current_time.day, hour=int(time[0]), minute=int(time[1]))
        logger.info(f"Cron style grading should begin at {start_time}")

        time_diff = (start_time - current_time).total_seconds()
    else:
        time_diff = 0
    
    globals.cron_delay = globals.cron_delay + time_diff


def run_cron_thread():
    '''
    This method is meant to be run inside a thread. 
    The method will run do_grade on a timer (similar to a cron job)
    '''

    limit = globals.cron_limit
    logger.info(f"Starting cron thread with interval {globals.cron_interval}. Grading is limited to running {limit} times.")

    cron_attempts = 0
    while globals.cron_limit != 0:
        cron_attempts += 1
        globals.cron_limit = globals.cron_limit - 1
        globals.submit_time = datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")
        logger.info(f"Starting cron grading attempt number {cron_attempts}")
        globals.results, globals.tokens = do_grade()
        logger.info(f"Results of cron grading attempt number {cron_attempts}: {globals.results}")
        sleep(globals.cron_interval)
    
    logger.info(f"The number of grading attempts ({limit}) has been exhausted. No more grading will take place.")
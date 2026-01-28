#!/usr/bin/env python3
import subprocess
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

logger = logging.getLogger(__name__)

SCRIPTS = [
    "/custom_scripts/graderDoor.py",
    "/custom_scripts/graderLights.py",
]

def run_script(path):
    """Run a grading script and stream its stdout/stderr."""
    logger.info(f"\n=== Running {path} ===")
    result = subprocess.run(
        [path],
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    return result.returncode

def gradeUsername(username):
    logger.info(f"Checking provided username: {username}")
    if username == "MLin2":
        print(f"tokenGradStudent: Success -- Correct username provided")
    elif username == "MLin2@ssu.edu":
        print(f"tokenGradStudent: Failed -- Username, not email.")
    else:
        print(f"tokenGradStudent: Failed -- That is not the username of the student.")
    

def main():
    exit_code = 0
    
    if len(sys.argv) > 1:
        gradeUsername(sys.argv[1])
    else:
        logger.info("No username provided.")
    
    for script in SCRIPTS:
        rc = run_script(script)
        if rc != 0:
            exit_code = rc
    sys.exit(exit_code)

if __name__ == "__main__":
    main()

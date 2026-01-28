#!/usr/bin/env python3
import subprocess
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

SCRIPTS = [
    "/custom_scripts/gradeInternalFixed.py",
    "/custom_scripts/gradeInternalRemoval.py",
    "/custom_scripts/gradePublicFixed.py",
    "/custom_scripts/gradePublicRemoval.py",
]

def run_script(path):
    """Run a grading script and stream its stdout/stderr."""
    logging.info(f"\n=== Running {path} ===")
    result = subprocess.run(
        [path],
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    return result.returncode

def main():
    exit_code = 0
    for script in SCRIPTS:
        rc = run_script(script)
        if rc != 0:
            exit_code = rc
    sys.exit(exit_code)

if __name__ == "__main__":
    main()

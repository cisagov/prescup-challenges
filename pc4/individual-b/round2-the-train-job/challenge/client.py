
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import requests


SCHEDULE_FILE = "schedule.py"


def main():
    with open(SCHEDULE_FILE) as f:
        content = f.read()

    r = requests.post("http://localhost:8000/upload",
                      json={"content": content})
    print(r.text)


if __name__ == "__main__":
    main()


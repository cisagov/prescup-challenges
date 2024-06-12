#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# Challenge grading scripts are run as root,
# so we need to modify the import path.
import sys  # noqa: F401
sys.path = ['/home/user/.local/lib/python3.10/site-packages'] + sys.path  # noqa: F401

from dataclasses import dataclass
import paramiko
from paramiko.client import AutoAddPolicy
import requests
from requests.exceptions import ConnectionError, Timeout, JSONDecodeError


@dataclass
class AirlockFields:
    id: str
    outer_open: bool
    inner_open: bool
    pressurized: bool


def part_1() -> str:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy)
    ssh.connect('10.10.10.20', username='user',
                key_filename='/home/user/.ssh/id_rsa')
    _, ssh_stdout, _ = ssh.exec_command(
        'curl 10.3.3.3:3000/airlocks --connect-timeout 2')

    output = ssh_stdout.read().strip()

    if output:
        return 'Failure - Insider threat is still able to reach the API'

    try:
        requests.get('http://10.3.3.3:3000/airlocks', timeout=2)
    except (ConnectionError, Timeout):
        return 'Failure - API is not reachable from the challenge server'

    return 'Success'


def part_2() -> str:
    try:
        resp = requests.get('http://10.3.3.3:3000/airlocks/cargo', timeout=2)
    except (ConnectionError, Timeout):
        return 'Failure - API is not reachable from the challenge server'

    try:
        data = resp.json()
    except JSONDecodeError:
        return 'Failure - API did not return valid JSON'

    try:
        airlock = AirlockFields(**data)
    except TypeError:
        return 'Failure - API response JSON was missing required fields'

    if (airlock.id == 'cargo'
        and airlock.outer_open is False
        and airlock.inner_open is False
            and airlock.pressurized is True):
        return 'Success'

    return ('Failure - Airlock was not correctly set - current setting is: '
            f'{{id: {airlock.id}, '
            f'outer_open: {airlock.outer_open}, '
            f'inner_open: {airlock.inner_open}, '
            f'pressurized: {airlock.pressurized}}}')


def grade_challenge():
    results = {
        'GradingCheck1': part_1(),
        'GradingCheck2': part_2(),
    }

    for key, value in results.items():
        print(key, ' : ', value)


if __name__ == '__main__':
    grade_challenge()

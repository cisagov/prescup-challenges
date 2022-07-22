
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from enum import Enum
import requests


SERVER = 'http://localhost'
PORT = 12000


class Reverse:
    @staticmethod
    def action(value):
        try:
            return value[::-1]
        except Exception as e:
            print(f"Reverse.action raised an exception: {str(e)}")
            return None


class RotateForward:
    @staticmethod
    def action(value):
        try:
            return value[-1:] + value[0:-1]
        except Exception as e:
            print(f"RotateForward.action raised an exception: {str(e)}")
            return None


class RotateBackward:
    @staticmethod
    def action(value):
        try:
            return value[1:] + value[0:1]
        except Exception as e:
            print(f"RotateBackward.action raised an exception: {str(e)}")
            return None


class SplitSwap:
    @staticmethod
    def action(value):
        try:
            # For anyone not familiar with Python 3, the // forces an int division result. The usual / returns a float.
            mid = len(value) // 2
            return value[mid:] + value[:mid]
        except Exception as e:
            print(f"SplitSwap.action raised an exception: {str(e)}")
            return None


class Actions(Enum):
    reverse = Reverse()
    rotate_forward = RotateForward()
    rotate_backward = RotateBackward()
    split_swap = SplitSwap()


def start_flag():
    return requests.get(f'{SERVER}:{PORT}/start').text


def submit(value):
    return requests.get(f'{SERVER}:{PORT}/submit/{value}').text


def reset():
    return requests.get(f'{SERVER}:{PORT}/reset').text


if __name__ == '__main__':
    action_list = list(Actions)

    response = start_flag()

    if response == 'needs_reset':
        print('Server needs to be reset...')
        print(reset())
        response = start_flag()

    try:
        to_process, action_name = response.rsplit('|', 1)
    except ValueError:
        print(f'{response}')
        exit()


    while True:
        for action in action_list:
            if action.name == action_name:
                print(f'Matched action {action.name}')
                processed = action.value.action(to_process)
                print(f'Processed action {action.name} on {to_process} to get {processed}')
                response = submit(processed)
                print(f'New string is {response}')
                break
        try:
            to_process, action_name = response.rsplit('|', 1)
        except ValueError:
            break


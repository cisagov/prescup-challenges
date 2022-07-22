
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from enum import Enum
import random
import string
import time

from flask import Flask
server = Flask(__name__)


# Oddly, Enums do not behave correctly when assigned a function. So I'll just assign a thin wrapper class to each
# Enum entry instead...
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


class GameState:
    MAX_STRING = 10000

    def __init__(self):
        self.failed_attempt = False
        self.last_timer = None
        self.last_action = random.choice(list(Actions))
        self.last_string = self.generate_string()

    def check_time(self):
        new_timer = time.time()
        if new_timer - self.last_timer < 2:
            self.last_timer = new_timer
            return True

    def get_state(self):
        return self.last_string + '|' + self.last_action.name

    def init_flag(self):
        if not self.last_timer:
            self.last_timer = time.time()
            return self.get_state()
        return 'needs_reset'

    def submit(self, value):
        if self.failed_attempt:
            return 'needs_reset'
        result = None
        if value == self.last_action.value.action(self.last_string):
            if len(self.last_string) > self.MAX_STRING:
                result = retrieve_flag("flag.txt")
            else:
                self.last_action = random.choice(list(Actions))
                old_str_len = len(self.last_string)
                self.last_string = self.generate_string(old_str_len, 2 * old_str_len)
                result = self.get_state()
        if not result:
            return 'incorrect_submission'
        if not self.check_time():
            self.failed_attempt = True
            return 'timed_out'
        return result

    @staticmethod
    def generate_string(min_len=8, max_len=16):
        string_size = random.randint(min_len, max_len)
        new_string = ''
        for _ in range(string_size):
            new_string += random.choice(string.ascii_letters)
        return new_string


def retrieve_flag(filename):
    try:
        with open(filename) as f:
            contents = f.read()
    except OSError:
        return 'Unable to open flag file. Please report this error to support with your support code.'
    else:
        return contents.strip()


@server.route('/start')
def start_flag():
    return GLOBAL_STATE.init_flag()


@server.route('/submit/<value>')
def submit_flag(value):
    return GLOBAL_STATE.submit(value)


@server.route('/reset')
def reset():
    global GLOBAL_STATE
    GLOBAL_STATE = GameState()
    return 'reset_ack'


def main():
    server.run(host="0.0.0.0", port=12000)


if __name__ == '__main__':
    GLOBAL_STATE = GameState()
    main()


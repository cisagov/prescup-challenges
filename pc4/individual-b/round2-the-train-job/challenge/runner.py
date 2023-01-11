
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sys
from datetime import datetime, timezone

from jose import jwt
from RestrictedPython import (
    compile_restricted,
    safe_builtins,
    limited_builtins,
    utility_builtins,
)
import RestrictedPython.transformer
import requests


class Scheduler:
    schedule: dict
    counter: int

    @classmethod
    def init(cls):
        cls.schedule = {}
        cls.counter = 1

    @classmethod
    def at_time(cls, timestamp_utc: float, destination: str):
        time = datetime.fromtimestamp(timestamp_utc, timezone.utc)
        cls.schedule[cls.counter] = (time, destination)
        cls.counter += 1

    @classmethod
    def cycle(cls):
        current_time = datetime.utcnow()
        for index in list(cls.schedule.keys()):
            time, destination = cls.schedule[index]
            if current_time >= time:
                move_train(destination)
                del cls.schedule[index]


def move_train(destination: str):
    key = sys.argv[2]
    token = jwt.encode({"aud": "1"}, key, algorithm="HS256")
    requests.post(
        "http://train:8001/train/move",
        params={"destination": destination},
        headers={"Authorization": f"Bearer {token}"},
    )


class PrintPolicy:
    @staticmethod
    def _call_print(value: str):
        print(value)


RestrictedPython.transformer.ALLOWED_FUNC_NAMES = (
    RestrictedPython.transformer.ALLOWED_FUNC_NAMES
    | frozenset(
        [
            "__bool__",
            "__del__",
            "__delattr__",
            "__delete__",
            "__getattr__",
            "__get__",
            "__init__",
            "__repr__",
            "__set__",
            "__str__",
        ]
    )
)

ALLOWED_IMPORTS = frozenset(
    [
        "array",
        "bisect",
        "calendar",
        "collections",
        "datetime",
        "heapq",
        "re",
        "string",
        "time",
        "typing",
        "unittest",
        "zoneinfo",
    ]
)


def import_guard(name, *args):
    if name in ALLOWED_IMPORTS:
        return __import__(name, *args)
    else:
        raise ImportError(f"{name} is not an allowed import.")


def main():
    Scheduler.init()
    utility_globals = {
        "__builtins__": safe_builtins
        | limited_builtins
        | utility_builtins
        | {"__import__": import_guard},
        "scheduler": Scheduler,
        "__metaclass__": type,
        "__name__": "imported",
        "_print_": lambda p: PrintPolicy,
        "_write_": lambda w: w,
        "getattr": lambda o, i: getattr(o, i),
        "_getitem_": lambda o, i: o[i],
    }

    file_name = sys.argv[1]
    with open(file_name) as f:
        result = compile_restricted(f.read(), filename=file_name, mode="exec")
    locals_dict = {}
    exec(result, utility_globals, locals_dict)

    while Scheduler.schedule:
        Scheduler.cycle()


if __name__ == "__main__":
    main()


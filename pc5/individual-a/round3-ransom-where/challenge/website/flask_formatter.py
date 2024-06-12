
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import logging
from typing import List, Tuple
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen
import re

PATTERN = '\$\{\{(.+?)\}\}'
SEACH_CLASS_NAME = "LogSubstitutor"


def parse_url(pattern: str) -> Tuple[bool, str, dict]:
    try:
        result = urlparse(pattern)
        if any([result.scheme, result.netloc]):
            parsed_url = "{}://{}{}".format(result.scheme, result.netloc,result.path)
            parameters = parse_qs(result.query)
            return True, parsed_url, parameters
    except:
        return False, None, None


def execute_object(data: str, params: dict) -> str:
    exec(data, globals())
    class_repr = eval(SEACH_CLASS_NAME)
    result = str(class_repr(**params))
    return result


def check_substitute_pattern(record_message: str) -> str:
    compiled_re = re.compile(PATTERN)
    matched_iter = compiled_re.finditer(record_message)
    iter = 0
    for match in matched_iter:
        found_str = match.group(1)
        try:
            ret, url, params = parse_url(found_str)
            if not ret:
                raise Exception()

            with urlopen(url, timeout=5) as response:
                eval_data = response.read()
            eval_result = execute_object(eval_data, params)
            record_message = re.sub(PATTERN, eval_result, record_message, iter)
            iter = iter + 1
        except Exception as e:
            iter += 1
            continue

    return record_message


class ShellishFormatter(logging.Formatter):
    def __init__(self):
        super(ShellishFormatter, self).__init__()

    def format(self, record: logging.LogRecord) -> str:
        # this is the default format function used by CPython's logging
        # library. We are retaining the same. But check_substitute_pattern
        # is called on the formatted string to make pattern substitution.
        record.message = record.getMessage()
        if self.usesTime():
            record.asctime = self.formatTime(record, self.datefmt)
        s = self.formatMessage(record)
        s = check_substitute_pattern(s)
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            if s[-1:] != "\n":
                s = s + "\n"
            s = s + record.exc_text
        if record.stack_info:
            if s[-1:] != "\n":
                s = s + "\n"
            s = s + self.formatStack(record.stack_info)
        return s


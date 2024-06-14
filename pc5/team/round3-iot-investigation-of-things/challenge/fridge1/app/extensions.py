
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler
import logging


class CustomLogger(logging.Logger):
    def _log(self, level, msg, args, exc_info=None, extra=None, stack_info=False):
        if extra is None:
            extra = {}
        super()._log(level, msg, args, exc_info, extra, stack_info)


global device_logger
logging.setLoggerClass(CustomLogger)

# New attempt
custom_handler = logging.StreamHandler()
custom_handler.setFormatter(logging.Formatter(f'Device Logger | %(device)s | %(status)s |%(message)s'))
device_logger = logging.getLogger('hub')
device_logger.setLevel(logging.INFO)
device_logger.addHandler(custom_handler)

logging.basicConfig(level=logging.INFO,format="%(message)s")

global db
db = SQLAlchemy()

global scheduler
scheduler = APScheduler()

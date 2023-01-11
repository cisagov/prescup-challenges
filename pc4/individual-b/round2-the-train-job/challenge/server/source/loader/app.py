
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os
from subprocess import run, PIPE, STDOUT

from pydantic import BaseModel
from starlite import Starlite, Controller, post, MediaType


RUNNER_NAME = "runner.py"
SCHEDULE_NAME = "schedule.py"
DEBUG_MODE = bool(os.getenv("DEBUG"))


class FileUpload(BaseModel):
    content: str


class ScheduleOutput(BaseModel):
    output: str


class Uploader(Controller):
    @post(path="/upload", media_type=MediaType.JSON)
    async def upload(self, data: FileUpload) -> ScheduleOutput:
        with open(SCHEDULE_NAME, "w") as f:
            f.write(data.content)
        result = run(
            ["python", RUNNER_NAME, SCHEDULE_NAME, os.getenv("TRAINKEY") or ""],
            stdout=PIPE,
            stderr=STDOUT,
        )

        return ScheduleOutput(output=result.stdout.decode())


app = Starlite(route_handlers=[Uploader], debug=DEBUG_MODE)


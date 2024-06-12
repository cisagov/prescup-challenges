
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import asyncio
from functools import partial
from json import dumps
from logging import debug, exception, basicConfig
import os
import random
from typing import Callable

from client import ApiClient


LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING")
TEST_MODE = os.environ.get("TEST_MODE", False)
basicConfig(level=LOG_LEVEL)


async def update_list(endpoint_func: Callable, data_list: list):
    data = await endpoint_func()
    data_list.clear()
    data_list.extend([el.id for el in data])
    debug(f"{endpoint_func} updated data list with {dumps(data_list)}")


async def interact_one(endpoint_func: Callable, data_list: list):
    el = random.choice(data_list)
    await endpoint_func(el)
    debug(f"{endpoint_func} called")


async def main():
    airlocks = list()
    cameras = list()
    comms = list()
    doors = list()
    envs = list()
    hydroponics = list()
    powers = list()

    endpoints = []

    endpoints.append(partial(update_list, ApiClient.Airlock.get_all, airlocks))
    endpoints.append(partial(update_list, ApiClient.Camera.get_all, cameras))
    endpoints.append(partial(update_list, ApiClient.Comms.get_all, comms))
    endpoints.append(partial(update_list, ApiClient.Doors.get_all, doors))
    endpoints.append(
        partial(update_list, ApiClient.Environments.get_all, envs))
    endpoints.append(
        partial(update_list, ApiClient.Hydroponics.get_all, hydroponics))
    endpoints.append(partial(update_list, ApiClient.Power.get_all, powers))

    try:
        async with asyncio.TaskGroup() as tg:
            for item in endpoints:
                tg.create_task(item())
    except Exception as e:
        exception(f"Update exception group had a failure: {e}")

    slice_start = len(endpoints)

    endpoints.append(
        partial(interact_one, ApiClient.Airlock.get_one, airlocks))
    endpoints.append(
        partial(interact_one, ApiClient.Airlock.cycle_inward, airlocks)
    )
    endpoints.append(
        partial(interact_one, ApiClient.Airlock.cycle_outward, airlocks)
    )

    endpoints.append(partial(interact_one, ApiClient.Camera.get_one, cameras))
    endpoints.append(
        partial(interact_one, ApiClient.Camera.start_recording, cameras))
    endpoints.append(
        partial(interact_one, ApiClient.Camera.stop_recording, cameras))
    endpoints.append(partial(interact_one, ApiClient.Camera.activate, cameras))
    endpoints.append(
        partial(interact_one, ApiClient.Camera.deactivate, cameras))

    endpoints.append(partial(interact_one, ApiClient.Comms.get_one, comms))
    endpoints.append(partial(interact_one, ApiClient.Comms.activate, comms))
    endpoints.append(partial(interact_one, ApiClient.Comms.deactivate, comms))
    endpoints.append(partial(interact_one, ApiClient.Comms.toggle, comms))

    endpoints.append(partial(interact_one, ApiClient.Doors.get_one, doors))
    endpoints.append(partial(interact_one, ApiClient.Doors.open, doors))
    endpoints.append(partial(interact_one, ApiClient.Doors.close, doors))
    endpoints.append(partial(interact_one, ApiClient.Doors.toggle, doors))

    endpoints.append(
        partial(interact_one, ApiClient.Hydroponics.get_one, hydroponics))
    endpoints.append(
        partial(interact_one, ApiClient.Hydroponics.activate, hydroponics))
    endpoints.append(
        partial(interact_one, ApiClient.Hydroponics.deactivate, hydroponics))
    endpoints.append(
        partial(interact_one, ApiClient.Hydroponics.toggle, hydroponics))

    if TEST_MODE:
        try:
            async with asyncio.TaskGroup() as tg:
                for item in endpoints[slice_start:]:
                    tg.create_task(item())
        except Exception as e:
            exception(f"Single interaction task group had a failure: {e}")
    else:
        while True:
            call_count = random.randint(0, 4)
            try:
                async with asyncio.TaskGroup() as tg:
                    for _ in range(call_count):
                        item = random.choice(endpoints)
                        tg.create_task(item())
            except Exception as e:
                exception(f"Standard cycle task group had a failure: {e}")
            await asyncio.sleep(0.5)


if __name__ == '__main__':
    asyncio.run(main())


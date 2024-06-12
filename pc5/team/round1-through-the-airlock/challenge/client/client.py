
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from dataclasses import dataclass
from enum import Enum
from logging import error
import os

from httpx import AsyncClient, Response


API_URL = os.environ["API_URL"]


class HttpMethod(Enum):
    GET = "GET"
    PUT = "PUT"


async def _service_request_and_log(
    client: AsyncClient,
    method: HttpMethod,
    endpoint: str,
) -> Response:
    async with client:
        args = {
            "method": method.value,
            "url": endpoint,
        }

        request = client.build_request(**args)

        response = await client.send(request)
        if not response.is_success:
            error(
                f"HTTP Request to {response.url} returned {response.status_code}\n"
                f"HTTP Method was: {request.method}\n"
                f"Headers were: {request.headers}\n"
                f"Request Body was: {request.content}\n"
                f"Response content was: {response.content}\n"
            )

        return response


async def _api_request(
    method: HttpMethod,
    endpoint: str,
) -> Response:
    client = AsyncClient(base_url=API_URL, timeout=2.0)
    return await _service_request_and_log(client, method, endpoint)


async def _api_get(
    endpoint: str,
) -> Response:
    return await _api_request(HttpMethod.GET, endpoint)


async def _api_put(
    endpoint: str,
) -> Response:
    return await _api_request(HttpMethod.PUT, endpoint)


@dataclass
class AirlockFields:
    id: str
    outer_open: bool
    inner_open: bool
    pressurized: bool


@dataclass
class CameraFields:
    id: str
    active: bool
    recording: bool


@dataclass
class CommunicationFields:
    id: str
    active: bool


@dataclass
class DoorFields:
    id: str
    open: bool


@dataclass
class EnvironmentFields:
    id: str
    active: bool
    temperature: int


@dataclass
class HydroponicsFields:
    id: str
    active: bool


@dataclass
class PowerFields:
    id: str
    active: bool


class ApiClient:
    class Airlock:
        async def get_all() -> list[AirlockFields]:
            response = await _api_get("/airlocks")
            return [AirlockFields(**airlock) for airlock in response.json()]

        async def get_one(airlock_id: str) -> AirlockFields:
            response = await _api_get(f"/airlocks/{airlock_id}")
            return AirlockFields(**response.json())

        async def cycle_outward(airlock_id: str) -> AirlockFields:
            response = await _api_put(f"/airlocks/{airlock_id}/cycle_outward")
            return AirlockFields(**response.json())

        async def cycle_inward(airlock_id: str) -> AirlockFields:
            response = await _api_put(f"/airlocks/{airlock_id}/cycle_inward")
            return AirlockFields(**response.json())

    class Camera:
        async def get_all() -> list[CameraFields]:
            response = await _api_get("/cameras")
            return [CameraFields(**camera) for camera in response.json()]

        async def get_one(camera_id: str) -> CameraFields:
            response = await _api_get(f"/cameras/{camera_id}")
            return CameraFields(**response.json())

        async def start_recording(camera_id: str) -> CameraFields:
            response = await _api_put(f"/cameras/{camera_id}/start_recording")
            return CameraFields(**response.json())

        async def stop_recording(camera_id: str) -> CameraFields:
            response = await _api_put(f"/cameras/{camera_id}/stop_recording")
            return CameraFields(**response.json())

        async def activate(camera_id: str) -> CameraFields:
            response = await _api_put(f"/cameras/{camera_id}/activate")
            return CameraFields(**response.json())

        async def deactivate(camera_id: str) -> CameraFields:
            response = await _api_put(f"/cameras/{camera_id}/deactivate")
            return CameraFields(**response.json())

    class Comms:
        async def get_all() -> list[CommunicationFields]:
            response = await _api_get("/comms")
            return [CommunicationFields(**comm) for comm in response.json()]

        async def get_one(comm_id: str) -> CommunicationFields:
            response = await _api_get(f"/comms/{comm_id}")
            return CommunicationFields(**response.json())

        async def activate(comm_id: str) -> CommunicationFields:
            response = await _api_put(f"/comms/{comm_id}/activate")
            return CommunicationFields(**response.json())

        async def deactivate(comm_id: str) -> CommunicationFields:
            response = await _api_put(f"/comms/{comm_id}/deactivate")
            return CommunicationFields(**response.json())

        async def toggle(comm_id: str) -> CommunicationFields:
            response = await _api_put(f"/comms/{comm_id}/toggle")
            return CommunicationFields(**response.json())

    class Doors:
        async def get_all() -> list[DoorFields]:
            response = await _api_get("/doors")
            return [DoorFields(**comm) for comm in response.json()]

        async def get_one(door_id: str) -> DoorFields:
            response = await _api_get(f"/doors/{door_id}")
            return DoorFields(**response.json())

        async def open(door_id: str) -> DoorFields:
            response = await _api_put(f"/doors/{door_id}/open")
            return DoorFields(**response.json())

        async def close(door_id: str) -> DoorFields:
            response = await _api_put(f"/doors/{door_id}/close")
            return DoorFields(**response.json())

        async def toggle(door_id: str) -> DoorFields:
            response = await _api_put(f"/doors/{door_id}/toggle")
            return DoorFields(**response.json())

    class Environments:
        async def get_all() -> list[EnvironmentFields]:
            response = await _api_get("/env_ctrls")
            return [EnvironmentFields(**env_ctrl) for env_ctrl in response.json()]

    class Hydroponics:
        async def get_all() -> list[HydroponicsFields]:
            response = await _api_get("/hydroponics")
            return [HydroponicsFields(**comm) for comm in response.json()]

        async def get_one(hydroponics_id: str) -> HydroponicsFields:
            response = await _api_get(f"/hydroponics/{hydroponics_id}")
            return HydroponicsFields(**response.json())

        async def activate(hydroponics_id: str) -> HydroponicsFields:
            response = await _api_put(f"/hydroponics/{hydroponics_id}/activate")
            return HydroponicsFields(**response.json())

        async def deactivate(hydroponics_id: str) -> HydroponicsFields:
            response = await _api_put(f"/hydroponics/{hydroponics_id}/deactivate")
            return HydroponicsFields(**response.json())

        async def toggle(hydroponics_id: str) -> HydroponicsFields:
            response = await _api_put(f"/hydroponics/{hydroponics_id}/toggle")
            return HydroponicsFields(**response.json())

    class Power:
        async def get_all() -> list[PowerFields]:
            response = await _api_get("/power")
            return [PowerFields(**power) for power in response.json()]


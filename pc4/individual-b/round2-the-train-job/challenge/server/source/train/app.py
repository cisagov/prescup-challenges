
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from json import load
import os

from jose import jwt, JWTError
from starlite import (
    Starlite,
    Controller,
    post,
    Parameter,
    NotAuthorizedException,
    Response,
)
from starlite.enums import MediaType
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR

from trainnetwork import (
    TrainNetwork,
    DestinationDoesNotExistError,
    SourceDoesNotExistError,
    AlreadyAtDestinationError,
)


class Global:
    train_position: str = "Architect Colony"
    train_network: TrainNetwork

    @classmethod
    def init(cls):
        with open("network.json") as f:
            json_data = load(f)
        cls.train_network = TrainNetwork.from_dict(json_data)


class TrainController(Controller):
    path = "/train"

    @staticmethod
    def check_auth(auth_header: str) -> int:
        try:
            token = auth_header.split()[1]
            payload = jwt.decode(
                token,
                os.getenv("TRAINKEY") or "",
                algorithms=["HS256"],
                options={"verify_aud": False},
            )
            level = int(payload["aud"])
            if level <= 0:
                raise ValueError("level <= 0")
            return level
        except (JWTError, IndexError, ValueError):
            raise NotAuthorizedException("Authorization is invalid.")

    @post(path="/move")
    async def move(
        self, destination: str, auth_header: str = Parameter(header="Authorization")
    ) -> str | Response:
        auth_level = self.check_auth(auth_header)

        try:
            path = Global.train_network.find_path(
                Global.train_position, destination, auth_level
            )
        except AlreadyAtDestinationError:
            # This is okay - use the outro to check if the flag should be returned.
            pass
        except DestinationDoesNotExistError as e:
            return Response(
                {"detail": f"Destination {str(e)} does not exist."},
                status_code=HTTP_400_BAD_REQUEST,
                media_type=MediaType.JSON,
            )
        except SourceDoesNotExistError as e:
            return Response(
                {
                    "detail": f"Source {str(e)} does not exist. This is a server error that should not happen."
                },
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                media_type=MediaType.JSON,
            )
        else:
            if not path:
                raise NotAuthorizedException(
                    "There is no path to the destination with your current authorization level."
                )
            Global.train_position = destination

        if destination == "Miracle Colony":
            return os.getenv("TRAIN_FLAG")
        return ""


app = Starlite(route_handlers=[TrainController], on_startup=[Global.init])


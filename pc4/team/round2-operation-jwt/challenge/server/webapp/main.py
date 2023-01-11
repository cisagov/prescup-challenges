
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from logging import error
from traceback import format_exc

from starlite import (
    Starlite,
    StaticFilesConfig,
    OpenAPIConfig,
    OpenAPIController,
    get,
    MediaType,
    Request,
    Response,
)
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

from controllers.warehouse import Warehouse
from globals import Global
from settings import Settings


settings = Settings()


class VendoredOpenAPIController(OpenAPIController):
    @get(media_type=MediaType.HTML, include_in_schema=False)
    def redoc(self, request: Request) -> str:
        resp = super().redoc.fn(self, request)

        find = f"https://cdn.jsdelivr.net/npm/redoc@{self.redoc_version}/bundles/"
        replace = "/static/"

        return resp.replace(find, replace)


def http_500_handler(_r: Request, _e: Exception) -> Response:
    error(format_exc())
    return Response(
        media_type=MediaType.JSON, content="Internal Server Error", status_code=500
    )


app = Starlite(
    route_handlers=[Warehouse],
    openapi_config=OpenAPIConfig(
        title="Warehouse Manager",
        version="1.1",
        openapi_controller=VendoredOpenAPIController,
    ),
    on_startup=[Global.init],
    debug=settings.debug,
    static_files_config=[
        StaticFilesConfig(
            directories=["static"],
            path="/static",
        ),
    ],
    exception_handlers={HTTP_500_INTERNAL_SERVER_ERROR: http_500_handler},
)


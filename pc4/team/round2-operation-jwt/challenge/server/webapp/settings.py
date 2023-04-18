
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from pydantic import BaseSettings


class Settings(BaseSettings):
    debug: bool = False
    no_generate: bool = False
    db_file: str = ":memory:"

    jwt_secret: str = ""
    admin_secret: str = "b355bf0e59538fc3"

    oranges_flag: str = "0123456789abcdef"

    class Config:
        env_prefix = "inventory_"


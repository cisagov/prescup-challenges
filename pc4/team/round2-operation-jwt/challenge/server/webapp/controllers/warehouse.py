
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import logging
import traceback

from peewee import DoesNotExist
from jose import jwt, JWTError
from starlite import (
    Controller,
    post,
    get,
    NotAuthorizedException,
    NotFoundException,
    Parameter,
)

from models.item import PeeweeItem, Item
from models.inventory import PeeweeInventory, Inventory
from models.section import RestrictionLevel, PeeweeSection, Section
from settings import Settings


class Warehouse(Controller):
    path = "/warehouse"

    @staticmethod
    def check_auth(
        required_level: RestrictionLevel, auth_header: str
    ) -> RestrictionLevel:
        settings = Settings()
        try:
            token = auth_header.split()[1]
            contents = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=["HS256"],
                options={"verify_aud": False},
            )
            audience = contents.get("aud")
            token_level = getattr(RestrictionLevel, audience)
        except (IndexError, JWTError, AttributeError):
            logging.error(traceback.format_exc())
            raise NotAuthorizedException()
        if token_level.value < required_level.value:
            raise NotAuthorizedException()
        return token_level

    @staticmethod
    def check_admin_auth(auth_header: str):
        admin_key = Settings().admin_secret
        try:
            token = auth_header.split()[1]
            jwt.decode(token, admin_key, algorithms=["HS256"], audience="admin")
        except (IndexError, JWTError):
            logging.error(traceback.format_exc())
            raise NotAuthorizedException()

    @staticmethod
    def lookup_item(item_id: int) -> PeeweeItem:
        try:
            return PeeweeItem.get(PeeweeItem.id == item_id)
        except DoesNotExist:
            raise NotFoundException(f"Could not find an item with id {item_id}.")

    @staticmethod
    def lookup_inventory(inventory_id: int) -> PeeweeInventory:
        try:
            return PeeweeInventory.get(PeeweeInventory.id == inventory_id)
        except DoesNotExist:
            raise NotFoundException(
                f"Could not find an inventory with id {inventory_id}."
            )

    @staticmethod
    def lookup_section(section_id: int) -> PeeweeSection:
        try:
            return PeeweeSection.get(PeeweeSection.id == section_id)
        except DoesNotExist:
            raise NotFoundException(f"Could not find a section with id {section_id}.")

    @post(path="/move/{item_id:int}/{section_id:int}")
    def move_item(
        self,
        item_id: int,
        section_id: int,
        auth_header: str = Parameter(header="Authorization"),
    ) -> None:
        item_to_move = self.lookup_item(item_id)

        destination_section = self.lookup_section(section_id)

        if item_to_move.inventory.section == destination_section:
            return

        restriction_level = max(
            item_to_move.inventory.section.restriction_level,
            destination_section.restriction_level,
        )
        self.check_auth(RestrictionLevel(restriction_level), auth_header)

        destination_section.move_item(item_to_move)

    @get(path="/sections")
    def sections(
        self,
        recurse: bool = False,
        auth_header: str = Parameter(header="Authorization"),
    ) -> list[Section]:
        token_level = self.check_auth(RestrictionLevel.employees, auth_header)
        pw_sections = PeeweeSection.select().execute()
        return [
            pw_section.to_pydantic(recurse)
            for pw_section in filter(
                lambda s: s.restriction_level <= token_level.value,
                pw_sections,
            )
        ] + [
            pw_section.to_pydantic(False, True)
            for pw_section in filter(
                lambda s: s.restriction_level > token_level.value,
                pw_sections,
            )
        ]

    @get(path="/inventories")
    def inventories(
        self,
        recurse: bool = False,
        auth_header: str = Parameter(header="Authorization"),
    ) -> list[Inventory]:
        token_level = self.check_auth(RestrictionLevel.employees, auth_header)
        return [
            pw_inventory.to_pydantic(recurse)
            for pw_inventory in filter(
                lambda i: i.section.restriction_level <= token_level.value,
                PeeweeInventory.select().execute(),
            )
        ]

    @get(path="/items")
    def items(self, auth_header: str = Parameter(header="Authorization")) -> list[Item]:
        token_level = self.check_auth(RestrictionLevel.employees, auth_header)
        return [
            pw_item.to_pydantic()
            for pw_item in filter(
                lambda i: i.inventory.section.restriction_level <= token_level.value,
                PeeweeItem.select().execute(),
            )
        ]

    @post(path="/admin/construct", include_in_schema=False)
    def generate_objects(
        self,
        data: list[Section],
        auth_header: str = Parameter(header="Authorization"),
    ) -> list[Section]:
        self.check_admin_auth(auth_header)

        sections = [PeeweeSection.from_pydantic(section) for section in data]
        return [section.to_pydantic(True) for section in sections]


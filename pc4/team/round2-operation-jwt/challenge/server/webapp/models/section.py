
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from enum import Enum
from typing import Literal

from peewee import IntegerField
from playhouse.sqlite_ext import AutoIncrementField
from pydantic import BaseModel

from .base import PeeweeBase
from .inventory import Inventory, PeeweeInventory, CapacityError
from .item import Item, PeeweeItem


class RestrictionLevel(Enum):
    employees = 1
    managers = 2
    executives = 3


class Section(BaseModel):
    id: int | None = None

    inventories: list[Inventory] | Literal["REDACTED"] = []

    restriction_level: RestrictionLevel = RestrictionLevel.employees

    class Config:
        use_enum_values: True


class PeeweeSection(PeeweeBase):
    id = AutoIncrementField(primary_key=True)

    restriction_level = IntegerField()

    def add_item(self, item: Item) -> PeeweeItem:
        for inv in self.inventories:
            try:
                return inv.add_item(item)
            except CapacityError:
                continue
        else:
            raise CapacityError(f"Could not add item to section {self.id}.")

    def move_item(self, pw_item: PeeweeItem):
        for inv in self.inventories:
            try:
                inv.move_item(pw_item)
            except CapacityError:
                continue
            else:
                break
        else:
            raise CapacityError(f"Could not move item to section {self.id}.")

    def add_inventory(self, inventory: Inventory):
        pw_inventory = PeeweeInventory.from_pydantic(inventory, self)
        pw_inventory.save()

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        for inv in self.inventories:
            inv.save()

    @classmethod
    def from_pydantic(cls, section: Section) -> "PeeweeSection":
        pw_section, _ = cls.get_or_create(
            id=section.id,
            restriction_level=section.restriction_level.value,
        )
        if not isinstance(section.inventories, str):
            [PeeweeInventory.from_pydantic(inv, pw_section) for inv in section.inventories]
        return pw_section

    def to_pydantic(self, recurse=False, redacted=False) -> Section:
        inventories = (
            [inv.to_pydantic(recurse) for inv in self.inventories] if recurse else []
        )
        return Section(
            id=self.id,
            restriction_level=self.restriction_level,
            inventories=inventories if not redacted else "REDACTED",
        )


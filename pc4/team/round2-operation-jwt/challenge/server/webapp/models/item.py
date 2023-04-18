
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from enum import Enum

from peewee import TextField, IntegerField, DeferredForeignKey
from playhouse.sqlite_ext import AutoIncrementField
from pydantic import BaseModel

from .base import PeeweeBase


class ItemSize(Enum):
    SMALL = 1
    MEDIUM = 4
    LARGE = 9


class Item(BaseModel):
    id: int | None = None

    name: str
    size: ItemSize


class PeeweeItem(PeeweeBase):
    id = AutoIncrementField(primary_key=True)

    name = TextField()
    size = IntegerField()

    inventory = DeferredForeignKey("PeeweeInventory", backref="contents", null=True)

    @classmethod
    def from_pydantic(cls, item: Item, inventory: "PeeweeInventory") -> "PeeweeItem":
        pw_item, _ = cls.get_or_create(
            id=item.id, name=item.name, size=item.size.value, inventory=inventory
        )
        return pw_item

    def to_pydantic(self):
        return Item(id=self.id, name=self.name, size=self.size)


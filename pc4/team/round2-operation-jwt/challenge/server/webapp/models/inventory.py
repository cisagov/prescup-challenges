
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from peewee import IntegerField, DeferredForeignKey
from playhouse.sqlite_ext import AutoIncrementField
from pydantic import BaseModel

from .base import PeeweeBase
from .item import Item, ItemSize, PeeweeItem


class CapacityError(Exception):
    ...


class Inventory(BaseModel):
    id: int | None = None

    largest_item: ItemSize

    capacity: int
    contents: list[Item] = []


class PeeweeInventory(PeeweeBase):
    id = AutoIncrementField(primary_key=True)

    largest_item = IntegerField()

    capacity = IntegerField()

    section = DeferredForeignKey("PeeweeSection", backref="inventories")

    @property
    def current_stock(self):
        return sum(map(lambda item: item.size, self.contents))

    def _can_fit(self, item_size: int):
        return (
            item_size <= self.largest_item
            and self.current_stock + item_size <= self.capacity
        )

    def add_item(self, item: Item) -> PeeweeItem:
        if self._can_fit(item.size.value):
            return PeeweeItem.from_pydantic(item, self)
        else:
            raise CapacityError()

    def move_item(self, pw_item: PeeweeItem):
        if self._can_fit(pw_item.size):
            pw_item.inventory = self
            pw_item.save()
        else:
            raise CapacityError()

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        for item in self.contents:
            item.save()

    @classmethod
    def from_pydantic(
        cls, inventory: Inventory, section: "PeeweeSection"
    ) -> "PeeweeInventory":
        pw_inventory, _ = cls.get_or_create(
            id=inventory.id,
            largest_item=inventory.largest_item.value,
            capacity=inventory.capacity,
            section=section,
        )
        [PeeweeItem.from_pydantic(item, pw_inventory) for item in inventory.contents]
        return pw_inventory

    def to_pydantic(self, recurse=False) -> Inventory:
        items = [item.to_pydantic() for item in self.contents] if recurse else []
        return Inventory(
            id=self.id,
            largest_item=self.largest_item,
            capacity=self.capacity,
            contents=items,
        )


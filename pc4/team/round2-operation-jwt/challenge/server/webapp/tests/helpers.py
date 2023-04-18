
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from itertools import cycle
import os

import pytest

from globals import Global
from models.inventory import Inventory
from models.item import Item, ItemSize
from models.section import Section, RestrictionLevel
from settings import Settings


@pytest.fixture
def init():
    settings = Settings()
    if os.path.isfile(settings.db_file):
        os.remove(settings.db_file)
    Global.init()


def get_row_count(cls) -> int:
    return len(list(cls.select().execute()))


def get_pydantic_items(n_items: int) -> list[Item]:
    values = cycle((ItemSize.SMALL.value, ItemSize.MEDIUM.value, ItemSize.LARGE.value))
    return [
        Item(
            name=f"test{i}",
            size=next(values),
        )
        for i in range(n_items)
    ]


def get_pydantic_inventory(
    size: ItemSize = ItemSize.LARGE,
    capacity: int = 100_000_000,
    contents: list[Item] = None,
) -> Inventory:
    if contents is None:
        contents = []
    return Inventory(
        largest_item=size,
        capacity=capacity,
        contents=contents,
    )


def get_pydantic_section(
    inventories: list[Inventory] = None,
    restriction_level: RestrictionLevel = RestrictionLevel.employees,
) -> Section:
    if inventories is None:
        inventories = []
    return Section(inventories=inventories, restriction_level=restriction_level)


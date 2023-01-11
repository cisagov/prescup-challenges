
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import random

from models import (
    PeeweeBase,
    PeeweeSection,
    PeeweeInventory,
    PeeweeItem,
    Section,
    Inventory,
    Item,
    ItemSize,
    RestrictionLevel,
)
from settings import Settings
import constants


class Global:
    settings: Settings
    generation_lookup: dict

    @classmethod
    def init(cls):
        cls.settings = Settings()
        cls.init_db()

        cls.generation_lookup = {
            RestrictionLevel.employees: {
                ItemSize.SMALL: constants.POSSIBLE_EMPLOYEE_ITEMS_SMALL,
                ItemSize.MEDIUM: constants.POSSIBLE_EMPLOYEE_ITEMS_MEDIUM,
                ItemSize.LARGE: constants.POSSIBLE_EMPLOYEE_ITEMS_LARGE,
            },
            RestrictionLevel.managers: {
                ItemSize.SMALL: constants.POSSIBLE_MANAGER_ITEMS_SMALL,
                ItemSize.MEDIUM: constants.POSSIBLE_MANAGER_ITEMS_MEDIUM,
                ItemSize.LARGE: constants.POSSIBLE_MANAGER_ITEMS_LARGE,
            },
            RestrictionLevel.executives: {
                ItemSize.SMALL: constants.POSSIBLE_EXECUTIVE_ITEMS_SMALL,
                ItemSize.MEDIUM: constants.POSSIBLE_EXECUTIVE_ITEMS_SMALL,
                ItemSize.LARGE: constants.POSSIBLE_EXECUTIVE_ITEMS_SMALL,
            },
        }

        if not cls.settings.no_generate:
            cls.generate_warehouse()

    @classmethod
    def init_db(cls):
        db = PeeweeBase._meta.database
        db.init(cls.settings.db_file)
        db.connect()
        db.create_tables((PeeweeItem, PeeweeSection, PeeweeInventory))

    @classmethod
    def generate_item(cls, restriction_level: RestrictionLevel, size_limit: ItemSize):
        name, size = random.choice(cls.generation_lookup[restriction_level][size_limit])
        return Item(
            name=name,
            size=size,
        )

    @classmethod
    def generate_inventory(
        cls,
        restriction_level: RestrictionLevel,
        size_limit: ItemSize = None,
        goal_inventory: bool = False,
    ):
        if size_limit is None:
            size_limit = random.choice(list(ItemSize))

        if goal_inventory:
            if size_limit.value < ItemSize.MEDIUM.value:
                size_limit = ItemSize.MEDIUM
        n_items = random.randint(5, 15)
        items = [
            cls.generate_item(restriction_level, size_limit) for _ in range(n_items)
        ]
        if goal_inventory:
            goal_item = Item(
                name=f"crate of oranges {Global.settings.oranges_flag}",
                size=ItemSize.MEDIUM,
            )
            items.append(goal_item)

        capacity = sum(map(lambda item: item.size.value, items)) + random.randint(
            10, 30
        )
        return Inventory(largest_item=size_limit, capacity=capacity, contents=items)

    @classmethod
    def generate_section(cls, restriction_level: RestrictionLevel):
        n_inventories = random.randint(1, 3)
        inventories = [
            cls.generate_inventory(
                restriction_level, size_limit=random.choice(list(ItemSize))
            )
            for _ in range(n_inventories)
        ]
        if restriction_level == RestrictionLevel.executives:
            inventories.append(
                cls.generate_inventory(
                    restriction_level, ItemSize.MEDIUM, goal_inventory=True
                )
            )

        return Section(inventories=inventories, restriction_level=restriction_level)

    @classmethod
    def generate_warehouse(cls):
        exec_section = cls.generate_section(RestrictionLevel.executives)
        manager_section = cls.generate_section(RestrictionLevel.managers)
        employee_sections = [
            cls.generate_section(RestrictionLevel.employees) for _ in range(6)
        ]

        [
            PeeweeSection.from_pydantic(section)
            for section in [exec_section] + [manager_section] + employee_sections
        ]


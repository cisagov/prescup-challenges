
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from helpers import (
    get_pydantic_section,
    get_pydantic_inventory,
    get_pydantic_items,
    get_row_count,
    init,
)
from models.inventory import PeeweeInventory
from models.item import PeeweeItem
from models.section import Section, PeeweeSection


def get_inventory_size(
    inventory_or_section: PeeweeSection | PeeweeInventory, index: int = None
) -> int:
    inventory = inventory_or_section
    if type(inventory) == PeeweeSection:
        inventory = inventory.inventories[index]
    return len(inventory.contents)


def test_item_from_pydantic(init):
    inventory = get_pydantic_inventory()
    section = get_pydantic_section([inventory])
    pw_section = PeeweeSection.from_pydantic(section)

    items = get_pydantic_items(2)

    assert get_row_count(PeeweeItem) == 0

    pw_section.add_item(items[0])
    assert get_row_count(PeeweeItem) == 1

    pw_section.add_item(items[1])
    assert get_row_count(PeeweeItem) == 2


def test_inventory_from_pydantic(init):
    section = get_pydantic_section()
    pw_section = PeeweeSection.from_pydantic(section)

    assert get_row_count(PeeweeInventory) == 0

    inventory = get_pydantic_inventory()
    PeeweeInventory.from_pydantic(inventory, pw_section)

    assert get_row_count(PeeweeInventory) == 1

    inventory = get_pydantic_inventory()
    PeeweeInventory.from_pydantic(inventory, pw_section)

    assert get_row_count(PeeweeInventory) == 2


def test_section_from_pydantic_once(init):
    assert get_row_count(PeeweeSection) == 0

    section = Section()
    PeeweeSection.from_pydantic(section)

    assert get_row_count(PeeweeSection) == 1

    section = Section()
    PeeweeSection.from_pydantic(section)

    assert get_row_count(PeeweeSection) == 2


def test_move_item(init):
    items = get_pydantic_items(1)
    inv_1 = get_pydantic_inventory(contents=items)
    inv_2 = get_pydantic_inventory()
    section = get_pydantic_section([inv_1, inv_2])

    pw_section = PeeweeSection.from_pydantic(section)

    assert get_inventory_size(pw_section, 0) == 1
    assert get_inventory_size(pw_section, 1) == 0

    pw_item = pw_section.inventories[0].contents[0]
    pw_item.inventory = pw_section.inventories[1]
    pw_item.save()

    assert get_inventory_size(pw_section, 0) == 0
    assert get_inventory_size(pw_section, 1) == 1


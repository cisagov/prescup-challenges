
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import logging
from functools import partial
import json

from jose import jwt
import pytest
from starlite.testing import TestClient

from globals import Global
from helpers import (
    get_pydantic_section,
    get_pydantic_inventory,
    get_pydantic_items,
    get_row_count,
    init,
)
from main import app
from models.inventory import PeeweeInventory
from models.item import ItemSize, PeeweeItem
from models.section import Section, PeeweeSection, RestrictionLevel
from settings import Settings


def token(aud: str, secret: str = ""):
    return jwt.encode({"aud": aud}, secret, algorithm="HS256")


def get_object_count(client: TestClient, endpoint: str, auth_token: str) -> int:
    return len(
        client.get(
            f"/warehouse{endpoint}", headers={"Authorization": f"Bearer {auth_token}"}
        ).json()
    )


@pytest.fixture
def employee():
    return token("employees")


@pytest.fixture
def manager():
    return token("managers")


@pytest.fixture
def executive():
    return token("executives")


@pytest.fixture
def admin():
    settings = Settings()
    return token("admin", settings.admin_secret)


def get_tester_by_level(url, auth_token, model, constructor_func, expected_results):
    with TestClient(app) as client:
        assert get_row_count(model) == 0

        caller = partial(
            client.get, url=url, headers={"Authorization": f"Bearer {auth_token}"}
        )

        r = caller()
        assert r.status_code == 200
        assert len(r.json()) == 0

        expected_row_count = 1
        for i, level in enumerate(RestrictionLevel):
            constructor_func(level)
            assert get_row_count(model) == expected_row_count
            expected_row_count += 1

            r = caller()
            assert r.status_code == 200
            if "sections" in url:
                restricted_sections = list(filter(lambda section: section["inventories"] == "REDACTED", r.json()))
                assert len(r.json()) - len(restricted_sections) == expected_results[i]
            else:
                assert len(r.json()) == expected_results[i]


def get_sections_constructor(level: RestrictionLevel) -> PeeweeSection:
    section = get_pydantic_section(restriction_level=level)
    return PeeweeSection.from_pydantic(section)


def test_get_sections_employee(init, employee):
    get_tester_by_level(
        "/warehouse/sections",
        employee,
        PeeweeSection,
        get_sections_constructor,
        (1, 1, 1),
    )


def test_get_sections_manager(init, manager):
    get_tester_by_level(
        "/warehouse/sections",
        manager,
        PeeweeSection,
        get_sections_constructor,
        (1, 2, 2),
    )


def test_get_section_executive(init, executive):
    get_tester_by_level(
        "/warehouse/sections",
        executive,
        PeeweeSection,
        get_sections_constructor,
        (1, 2, 3),
    )


def get_inventories_constructor(level: RestrictionLevel) -> PeeweeInventory:
    pw_section = get_sections_constructor(level)
    inventory = get_pydantic_inventory()
    return PeeweeInventory.from_pydantic(inventory, pw_section)


def test_get_inventories_employee(init, employee):
    get_tester_by_level(
        "/warehouse/inventories",
        employee,
        PeeweeInventory,
        get_inventories_constructor,
        (1, 1, 1),
    )


def test_get_inventories_manager(init, manager):
    get_tester_by_level(
        "/warehouse/inventories",
        manager,
        PeeweeInventory,
        get_inventories_constructor,
        (1, 2, 2),
    )


def test_get_inventories_executive(init, executive):
    get_tester_by_level(
        "/warehouse/inventories",
        executive,
        PeeweeInventory,
        get_inventories_constructor,
        (1, 2, 3),
    )


def get_items_constructor(level: RestrictionLevel) -> PeeweeItem:
    pw_inventory = get_inventories_constructor(level)
    item = get_pydantic_items(1).pop()
    return PeeweeItem.from_pydantic(item, pw_inventory)


def test_get_items_employee(init, employee):
    get_tester_by_level(
        "/warehouse/items", employee, PeeweeItem, get_items_constructor, (1, 1, 1)
    )


def test_get_items_manager(init, manager):
    get_tester_by_level(
        "/warehouse/items", manager, PeeweeItem, get_items_constructor, (1, 2, 2)
    )


def test_get_items_executive(init, executive):
    get_tester_by_level(
        "/warehouse/items", executive, PeeweeItem, get_items_constructor, (1, 2, 3)
    )


def test_generate(init, employee, admin):
    items = get_pydantic_items(1)
    inventory = get_pydantic_inventory(contents=items)
    section = get_pydantic_section(inventories=[inventory])

    with TestClient(app) as client:
        assert get_object_count(client, "/sections", employee) == 0
        assert get_object_count(client, "/inventories", employee) == 0
        assert get_object_count(client, "/items", employee) == 0

        r = client.post(
            "/warehouse/admin/construct",
            headers={"Authorization": f"Bearer {admin}"},
            json=[json.loads(section.json())],
        )
        assert len(r.json()) > 0

        assert get_object_count(client, "/sections", employee) == 1
        assert get_object_count(client, "/inventories", employee) == 1
        assert get_object_count(client, "/items", employee) == 1


def admin_construct(client: TestClient, admin_token: str, sections: list[Section]):
    r = client.post(
        "/warehouse/admin/construct",
        headers={"Authorization": f"Bearer {admin_token}"},
        json=list(map(json.loads, map(lambda s: s.json(), sections))),
    )
    assert r.status_code == 201
    return r


def test_move_success(init, executive, admin):
    with TestClient(app) as client:
        assert get_object_count(client, "/sections", executive) == 0
        assert get_object_count(client, "/inventories", executive) == 0
        assert get_object_count(client, "/items", executive) == 0

        items = get_pydantic_items(1)
        inventory_1 = get_pydantic_inventory(contents=items)
        inventory_2 = get_pydantic_inventory()
        section_1 = get_pydantic_section(inventories=[inventory_1])
        section_2 = get_pydantic_section(inventories=[inventory_2])

        r = admin_construct(client, admin, [section_1, section_2])
        assert get_object_count(client, "/sections", executive) == 2
        assert get_object_count(client, "/inventories", executive) == 2
        assert get_object_count(client, "/items", executive) == 1

        constructed_sections = r.json()
        for section in constructed_sections:
            if len(section["inventories"][0]["contents"]) > 0:
                containing_section = section
            else:
                empty_section = section

        client.post(
            url=(
                f"/warehouse/move/{containing_section['inventories'][0]['contents'][0]['id']}/"
                f"{empty_section['id']}"
            ),
            headers={"Authorization": f"Bearer {executive}"},
        )

        r = client.get(
            "/warehouse/sections",
            headers={"Authorization": f"Bearer {executive}"},
            params={"recurse": True},
        )
        assert r.status_code == 200

        sections = r.json()
        for section in sections:
            if containing_section["id"] == section["id"]:
                new_empty_section = section
            else:
                new_containing_section = section

        assert len(new_empty_section["inventories"][0]["contents"]) == 0
        assert len(new_containing_section["inventories"][0]["contents"]) == 1


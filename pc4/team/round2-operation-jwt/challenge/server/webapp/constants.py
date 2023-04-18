
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from models.item import ItemSize

POSSIBLE_EMPLOYEE_ITEMS_SMALL = [
    ("box of dice", ItemSize.SMALL),
    ("power drill", ItemSize.SMALL),
    ("box of nuts and bolts", ItemSize.SMALL),
]
POSSIBLE_EMPLOYEE_ITEMS_MEDIUM = [
    ("baseball bats", ItemSize.MEDIUM),
    ("water tank", ItemSize.MEDIUM),
    ("crate of blankets", ItemSize.MEDIUM),
    ("box of PPE", ItemSize.MEDIUM),
]
POSSIBLE_EMPLOYEE_ITEMS_LARGE = [("forklift", ItemSize.LARGE)]

POSSIBLE_MANAGER_ITEMS_SMALL = [("jar of pickles", ItemSize.SMALL)]
POSSIBLE_MANAGER_ITEMS_MEDIUM = [
    ("crate of hazardous chemical jugs", ItemSize.MEDIUM),
    ("audio system", ItemSize.MEDIUM),
]
POSSIBLE_MANAGER_ITEMS_LARGE = [("space moonshine tank", ItemSize.LARGE)]

POSSIBLE_EXECUTIVE_ITEMS_SMALL = [
    ("expensive watches", ItemSize.SMALL),
    ("moon sugar", ItemSize.SMALL),
    ("expensive champagne", ItemSize.SMALL),
]

POSSIBLE_EMPLOYEE_ITEMS_MEDIUM.extend(POSSIBLE_EMPLOYEE_ITEMS_SMALL)
POSSIBLE_EMPLOYEE_ITEMS_LARGE.extend(POSSIBLE_EMPLOYEE_ITEMS_MEDIUM)

POSSIBLE_MANAGER_ITEMS_SMALL.extend(POSSIBLE_EMPLOYEE_ITEMS_SMALL)
POSSIBLE_MANAGER_ITEMS_MEDIUM.extend(POSSIBLE_EMPLOYEE_ITEMS_MEDIUM)
POSSIBLE_MANAGER_ITEMS_LARGE.extend(POSSIBLE_MANAGER_ITEMS_LARGE)

POSSIBLE_EXECUTIVE_ITEMS_SMALL.extend(POSSIBLE_EMPLOYEE_ITEMS_SMALL)


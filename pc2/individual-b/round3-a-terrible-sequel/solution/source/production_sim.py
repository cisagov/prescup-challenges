
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from collections import Counter
import random


class Item:
    def __init__(self, name: str):
        self.name = name


class Recipe:
    def __init__(self, required_time_steps: int, input_materials, output_materials):
        self.required_time_steps = required_time_steps
        self.input_materials = input_materials
        self.output_materials = output_materials


class ProductionError(Exception):
    pass


class NotEnoughInventoryError(ProductionError):
    pass


class NotEnoughMachinesError(ProductionError):
    pass


class ProductionRun:
    def __init__(self, recipe: Recipe, finish_step: int):
        self.recipe = recipe
        self.finish_step = finish_step


class ProductionManager:
    def __init__(self, items: [Item], inventory: {Item: int}, recipes: [Recipe], machines_available: int):
        self.items = items
        self.inventory = Counter(inventory)
        self.recipes = recipes
        self.machines_available = machines_available
        self.runs = []
        self.current_step = 0

    def start_run(self, recipe: Recipe):
        if self.machines_available < 1:
            raise NotEnoughMachinesError

        # Before taking resources, make sure we have everything required.
        for item, amount in recipe.input_materials:
            if self.inventory[item] < amount:
                raise NotEnoughInventoryError

        # Now we actually take all of the required materials.
        for item, amount in recipe.input_materials:
            self.inventory[item] -= amount

        self.machines_available -= 1

        finish_step = self.current_step + recipe.required_time_steps
        new_run = ProductionRun(recipe, finish_step)

        self.runs.append(new_run)

    def simulate_step(self):
        incomplete_runs = []
        for run in self.runs:
            if run.finish_step <= self.current_step:
                for item, amount in run.recipe.output_materials:
                    self.inventory[item] += amount
                self.machines_available += 1
            else:
                incomplete_runs.append(run)

        self.runs = incomplete_runs

    def generate_runs(self):
        # Internally keep track of which recipes have either succeeded, or we have not yet tried.
        valid_recipes = list(self.recipes)

        # Then each time we get an error, we remove our random choice from this tracking until it's empty.
        while valid_recipes:
            choice = random.choice(valid_recipes)
            try:
                self.start_run(choice)
            except ProductionError:
                valid_recipes.remove(choice)

    def run_simulation(self, stop_step: int):
        for _ in range(self.current_step, stop_step):
            self.generate_runs()
            self.simulate_step()
            self.current_step += 1


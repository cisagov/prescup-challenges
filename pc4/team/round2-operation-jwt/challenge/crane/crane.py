
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from functools import partial
from itertools import count
import requests
from requests import ConnectionError
import tkinter as tk
from tkinter import ttk

from warehouse_security import get_token

url_base = "http://localhost:8000"


class App(ttk.Frame):
    def __init__(self, root, *args, **kwargs):
        super().__init__(root, *args, **kwargs)

        self.server_data = []

        self._status_text = tk.StringVar()
        self._status = "Starting..."

        self._section_text = tk.StringVar()
        self._selected_section = None

        self._inventory_text = tk.StringVar()
        self._selected_inventory = None

        self._item_text = tk.StringVar()
        self._selected_item = None

        self._dest_text = tk.StringVar()
        self._selected_dest = None

        status_label = ttk.Label(self, textvariable=self._status_text)
        status_label.grid(row=1, column=1, columnspan=3, sticky="nsew")

        move_button = ttk.Button(self, text="Move", command=self._move)
        move_button.grid(row=1, column=4, sticky="nsew")

        section_label = ttk.Label(self, textvariable=self._section_text)
        section_label.grid(row=2, column=1, sticky="nsew")

        inventory_label = ttk.Label(self, textvariable=self._inventory_text)
        inventory_label.grid(row=2, column=2, sticky="nsew")

        contents_label = ttk.Label(self, textvariable=self._item_text)
        contents_label.grid(row=2, column=3, sticky="nsew")

        mover_label = ttk.Label(self, textvariable=self._dest_text)
        mover_label.grid(row=2, column=4, sticky="nsew")

        self.dest_buttons = []
        self.item_buttons = []
        self.inventory_buttons = []
        self.section_buttons = []

        self.sections = {}
        self.inventories = {}
        self.items = {}

        self._sync()

    def get_status(self):
        return self._status_text.get()

    def set_status(self, value):
        self._status_text.set(f"Status: {value}")

    _status = property(get_status, set_status)

    def get_selected_section(self):
        return self._selected_section_id

    def set_selected_section(self, value):
        text = "Sections"
        if value:
            text += f" ({value} selected)"
        self._section_text.set(text)
        self._selected_section_id = value

    _selected_section = property(get_selected_section, set_selected_section)

    def get_selected_inventory(self):
        return self._selected_inventory_id

    def set_selected_inventory(self, value):
        text = "Inventory"
        if value:
            text += f" ({value} selected)"
        self._inventory_text.set(text)
        self._selected_inventory_id = value

    _selected_inventory = property(
        get_selected_inventory, set_selected_inventory)

    def get_selected_item(self):
        return self._selected_item_id

    def set_selected_item(self, value):
        text = "Item"
        if value:
            text += f" ({value} selected)"
        self._item_text.set(text)
        self._selected_item_id = value

    _selected_item = property(get_selected_item, set_selected_item)

    def get_selected_dest(self):
        return self._selected_dest_id

    def set_selected_dest(self, value):
        text = "Destination"
        if value:
            text += f" ({value} selected)"
        self._dest_text.set(text)
        self._selected_dest_id = value

    _selected_dest = property(get_selected_dest, set_selected_dest)

    def _select_destination(self, section_id: int = None):
        if self._selected_dest == section_id or section_id is None:
            self._selected_dest = None
            return
        self._selected_dest = section_id

    def _sync_destinations(self, item_id: int = None):
        for button in self.dest_buttons:
            button.destroy()
        self._select_destination()
        if self._selected_item == item_id or item_id is None:
            self._selected_item = None
            return
        self._selected_item = item_id
        self.dest_buttons = []

        item = self.items[item_id]
        root_section = item["root_section"]
        counter = count(3)
        for section in self.sections.values():
            if section["id"] == root_section["id"]:
                continue
            callback = partial(self._select_destination, section["id"])
            button = ttk.Button(
                self,
                text=(
                    f"Section {section['id']}\n"
                    f"Restriction Level: {section['restriction_level']}"
                ),
                command=callback,
            )
            button.grid(row=next(counter), column=4, sticky="nsew")
            self.dest_buttons.append(button)

    def _sync_items(self, inventory_id: int = None):
        for button in self.item_buttons:
            button.destroy()
        self._sync_destinations()
        if self._selected_inventory == inventory_id or inventory_id is None:
            self._selected_inventory = None
            return
        self._selected_inventory = inventory_id
        self.item_buttons = []

        inventory = self.inventories[inventory_id]
        counter = count(3)
        for item in inventory["contents"]:
            callback = partial(self._sync_destinations, item["id"])
            button = ttk.Button(
                self,
                text=(
                    f"Item {item['id']}\n"
                    f"Name: {item['name']}\n"
                    f"Size: {item['size']}"
                ),
                command=callback,
            )
            button.grid(row=next(counter), column=3, sticky="nsew")
            self.item_buttons.append(button)

    def _sync_inventories(self, section_id: int = None):
        for button in self.inventory_buttons:
            button.destroy()
        self._sync_items()
        if self._selected_section == section_id or section_id is None:
            self._selected_section = None
            return
        self._selected_section = section_id
        self.inventory_buttons = []

        section = self.sections[section_id]
        if section["inventories"] == "REDACTED":
            label = ttk.Label(self, text="REDACTED")
            label.grid(row=3, column=2, sticky="nsew")
            self.inventory_buttons.append(label)
        else:
            counter = count(3)
            for inventory in section["inventories"]:
                callback = partial(self._sync_items, inventory["id"])
                button = ttk.Button(
                    self,
                    text=(
                        f"Inventory {inventory['id']}\n"
                        f"Largest Item Size: {inventory['largest_item']}\n"
                        f"Capacity {inventory['capacity']}"
                    ),
                    command=callback,
                )
                button.grid(row=next(counter), column=2, sticky="nsew")
                self.inventory_buttons.append(button)

    def _sync_sections(self):
        for button in self.section_buttons:
            button.destroy()
        self._sync_inventories()
        self.section_buttons = []
        counter = count(3)
        for section in self.server_data:
            callback = partial(self._sync_inventories, section["id"])
            button = ttk.Button(
                self,
                text=(
                    f"Section {section['id']}\n"
                    f"Restriction Level: {section['restriction_level']}"
                ),
                command=callback,
            )
            button.grid(row=next(counter), column=1, sticky="nsew")
            self.section_buttons.append(button)

    @staticmethod
    def _get_token():
        return get_token()

    def _sync(self):
        try:
            response = requests.get(
                f"{url_base}/warehouse/sections",
                params={"recurse": True},
                headers={"Authorization": f"Bearer {self._get_token()}"},
                timeout=1,
            )
        except ConnectionError:
            self._status = "Error connecting to the server. Please contact support."
        else:
            if response.status_code == 200:
                self._status = "Ok."
            else:
                self._status = (
                    "Server returned an unexpected status. Please contact support."
                )
                return

            self.server_data = sorted(
                response.json(),
                key=lambda section: section["restriction_level"],
                reverse=True,
            )

            for section in self.server_data:
                self.sections[section["id"]] = section
                if isinstance(section["inventories"], list):
                    for inventory in section["inventories"]:
                        self.inventories[inventory["id"]] = inventory
                        for item in inventory["contents"]:
                            item["root_section"] = section
                            self.items[item["id"]] = item

            self._sync_sections()

    def _move(self):
        if not self._selected_item:
            self._status = "Select an item and destination."
            return
        if not self._selected_dest:
            self._status = "Select a destination."
            return
        try:
            response = requests.post(
                f"{url_base}/warehouse/move/{self._selected_item_id}/{self._selected_dest_id}",
                headers={"Authorization": f"Bearer {self._get_token()}"},
                timeout=1,
            )
        except ConnectionError:
            self._status = "Error connecting to the server. Please contact support."
        else:
            if response.status_code == 201:
                self._status = "Ok."
            else:
                self._status = (
                    "Server returned an unexpected status. Please contact support."
                )
            self._sync()


def main():
    root = tk.Tk()
    root.title("Crane Operator Client")
    root.geometry("800x1000")

    app = App(root)
    app.grid_columnconfigure("all", minsize=200)
    app.grid_rowconfigure("all", minsize=70)
    app.pack()

    root.resizable(False, False)
    root.mainloop()


if __name__ == "__main__":
    main()


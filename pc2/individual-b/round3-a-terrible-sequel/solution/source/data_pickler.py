
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import pickle

import psycopg2

import production_sim as sim


def data_basic():
    items = [sim.Item("Gizmo"),
             sim.Item("Doodad"),
             sim.Item("Whatsit"),
             sim.Item("Spanner"),
             sim.Item("Thingamabob")]

    inventory = {}

    gizmo_recipe = sim.Recipe(10, [], [(items[0], 1)])
    doodad_recipe = sim.Recipe(80, [(items[0], 3)], [(items[1], 1)])
    whatsit_recipe = sim.Recipe(50, [(items[1], 8)], [(items[2], 3)])
    spanner_recipe = sim.Recipe(500, [(items[2], 1)], [(items[3], 2)])
    thingamabob_recipe = sim.Recipe(35, [(items[3], 100)], [(items[4], 1)])

    recipes = [gizmo_recipe,
               doodad_recipe,
               whatsit_recipe,
               spanner_recipe,
               thingamabob_recipe]

    machines = 20

    return items, inventory, recipes, machines


def main():
    try:
        with open('database.txt') as f:
            user, password, host, port, database = f.readline().strip().split(',')
    except Exception as e:
        print(f'Got an error trying to open database credentials file: {e}')
        return

    try:
        conn = psycopg2.connect(user=user,
                                password=password,
                                host=host,
                                port=port,
                                database=database)
    except Exception as e:
        print(f'Got an error trying to connect to PostgreSQL database: {e}')
        return

    cursor = conn.cursor()

    p = pickle.dumps(data_basic())

    cursor.execute('CREATE TABLE IF NOT EXISTS data (id integer PRIMARY KEY, seed_data bytea)')
    
    command = 'INSERT INTO data (id, seed_data) VALUES (1, %s) ON CONFLICT DO NOTHING'
    print(command % p)

    cursor.execute(command, (p,))

    conn.commit()

    cursor.close()

    conn.close()


if __name__ == '__main__':
    main()


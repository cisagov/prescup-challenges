
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import hashlib
import pickle
import random
import string
import os

from flask import Flask, jsonify
import psycopg2

import production_sim as sim


RESULTS_TABLE_NAME = 'results'
RESULTS_FIELDS = ('id', 'report_name', 'time_steps', 'final_inventory')
RESULTS_FIELD_TYPES = ('SERIAL PRIMARY KEY', 'text', 'integer', 'text')

ITEMS_TABLE_NAME = 'items'
ITEMS_FIELDS = ('id', 'item_name')
ITEMS_FIELD_TYPES = ('integer PRIMARY KEY', 'text')

INIT_DATA = None
PROD_MAN = None


def get_db_conn():
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

    return conn

def init_database(item_records):
    conn = get_db_conn()
    if not conn:
        return

    cursor = conn.cursor()

    items_field_decls = []
    for field_name, field_type in zip(ITEMS_FIELDS, ITEMS_FIELD_TYPES):
        items_field_decls.append(f'{field_name} {field_type}')
    items_fields_typed = '(' + ', '.join(items_field_decls) + ')'

    results_field_decls = []
    for field_name, field_type in zip(RESULTS_FIELDS, RESULTS_FIELD_TYPES):
        results_field_decls.append(f'{field_name} {field_type}')
    results_fields_typed = '(' + ', '.join(results_field_decls) + ')'

    items_fields_untyped = '(' + ', '.join(ITEMS_FIELDS) + ')'

    cursor.execute(f'CREATE TABLE IF NOT EXISTS {ITEMS_TABLE_NAME} {items_fields_typed}')
    for key, name in item_records:
        cursor.execute(f'INSERT INTO {ITEMS_TABLE_NAME} {items_fields_untyped} VALUES ({key}, {name}) ON CONFLICT DO NOTHING')
    cursor.execute(f'CREATE TABLE IF NOT EXISTS {RESULTS_TABLE_NAME} {results_fields_typed}')
    conn.commit()

    cursor.close()
    conn.close()

def prepare_result_records(final_inventory):
    inv_parts = []
    for item, count in final_inventory.items():
        inv_parts.append(f'{item.name}: {count}')
    return ', '.join(inv_parts)

def save_result(time_steps, final_inventory_str, name=None):
    conn = get_db_conn()
    if not conn:
        return

    cursor = conn.cursor()

    # [1:] because the first field is serial.
    fields = '(' + ', '.join(RESULTS_FIELDS[1:]) + ')'
    if not name:
        name = ''.join(random.choices(string.ascii_letters, k=16))

    cmd = f"INSERT INTO {RESULTS_TABLE_NAME} {fields} VALUES ('{name}', {time_steps}, '{final_inventory_str}');"
    print(cursor.mogrify(cmd))
    cursor.execute(cmd)
    conn.commit()

    cursor.close()
    conn.close()

def fetch_data():
    conn = get_db_conn()
    if not conn:
        return

    cursor = conn.cursor()

    try:
        cursor.execute('SELECT * FROM data')
        pickled_bytes = cursor.fetchone()[1]

        data = pickle.loads(pickled_bytes)
    except Exception:
        data = []

    cursor.close()

    conn.close()


    return data

def setup():
    global INIT_DATA
    try:
        INIT_DATA = fetch_data()
    except Exception as e:
        print(e)
        INIT_DATA = [[], [], [], []]
    try:
        item_names = [(i, f"'{item.name}'") for i, item in enumerate(INIT_DATA[0])]
    except Exception as e:
        print(e)
        INIT_DATA = [[], [], [], []]
        item_names = []
    init_database(item_names)
    reset_sim()

app = Flask(__name__)

@app.route('/')
def index():
    return 'Welcome to Inventory Simulator v0.1. Please report any bugs you find!'

@app.route('/reload')
def reload():
    # sys.exit doesn't work for Flask.
    os._exit(0)

@app.route('/reset')
def reset_sim():
    global PROD_MAN
    PROD_MAN = sim.ProductionManager(*INIT_DATA)

    return 'Simulation reset.'

@app.route('/run/<num_steps>/<save_name>')
def run_simulation(num_steps=100, save_name=None):
    PROD_MAN.run_simulation(int(num_steps))


    final_inventory = prepare_result_records(PROD_MAN.inventory)

    save_result(PROD_MAN.current_step, final_inventory, save_name)

    return final_inventory

@app.route('/results')
@app.route('/results/<name>')
def get_results(name=''):
    conn = get_db_conn()
    if not conn:
        return 'Failed to retrieve results.'

    cursor = conn.cursor()

    command = f'SELECT * FROM {RESULTS_TABLE_NAME}'
    if name:
        command += f" WHERE report_name = '{name}'"
    command += ';'

    print(command)

    cursor.execute(command)

    results = cursor.fetchall()


    cursor.close()
    conn.close()

    return jsonify(results)

if __name__ == '__main__':
    setup()
    app.run(host='0.0.0.0')


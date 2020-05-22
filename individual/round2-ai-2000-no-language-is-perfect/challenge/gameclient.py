"""
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
"""

import sys

import requests


SERVER = 'http://localhost:8000'


def game_req(path):
    r = requests.get(f'{SERVER}/{path}')
    return r.json()

def req_index():
    r = requests.get(f'{SERVER}')
    return r.text

def req_goods():
    return game_req('goods')

def req_buy(item_id, quantity):
    return game_req(f'buy/{item_id}/{quantity}')

def req_sell(item_id, quantity):
    return game_req(f'sell/{item_id}/{quantity}')

def req_travel():
    return game_req('travel')

def req_state():
    return game_req('state')

def req_reset():
    return game_req('reset')

def display_state():
    state = req_state()
    print('#########################')
    print('Inventory:')
    print(f"\tMoney: {state['money']}")
    print(f"\tBodyguards: {state['bodyguard_amt']}")
    print(f"\tCurrent staple goods: {state['staple_goods_amt']}")
    print(f"\tCurrent luxury goods: {state['luxury_goods_amt']}")
    print(f"\tCurrent weapons: {state['weapons_amt']}")
    print(f"\tCurrent armor: {state['armor_amt']}")
    print('')
    print('Prices in this town:')
    print(f"\tBodyguards | Hire: {state['bodyguard_buy_price']}")
    print(f"\tChallenge Flag | Buy: {state['challenge_flag_buy_price']}")
    print(f"\tStaple Goods | Buy: {state['staple_goods_buy_price']} "
          f"| Sell: {state['staple_goods_sell_price']}")
    print(f"\tLuxury Goods | Buy: {state['luxury_goods_sell_price']} "
          f"| Sell: {state['luxury_goods_sell_price']}")
    print(f"\tWeapons | Buy: {state['weapons_sell_price']} "
          f"| Sell: {state['weapons_sell_price']}")
    print(f"\tArmor | Buy: {state['armor_sell_price']} "
          f"| Sell: {state['armor_sell_price']}")
    print('#########################')

def display_actions():
    print('Possible actions:')
    print('\ttrade')
    print('\ttravel')
    print('\treset')
    print('\tquit')

def handle_buy():
    goods = req_goods()
    goods = sorted(goods.items(), key=lambda t: t[1]['id'])
    
    while True:
        for k, v in goods:
            print(f'ID: {v["id"]} - Type: {k} - Price: {v["buy"]}')
        print('Enter the ID of the item you want to buy followed by '
              'the amount or type "back" to return to the previous menu.')
        inp = input()
        if inp == 'back':
            return
        try:
            id_, quantity = inp.split()
        except ValueError:
            continue
        status = req_buy(id_, quantity)['status']
        print('')
        print(status)
        print('')

def handle_sell():
    goods = req_goods()
    goods = sorted(goods.items(), key=lambda t: t[1]['id'])
    
    while True:
        for k, v in goods:
            if v['sell'] is None:
                continue
            print(f'ID: {v["id"]} - Type: {k} - Price: {v["sell"]}')
        print('Enter the ID of the item you want to sell followed by '
              'the amount or type "back" to return to the previous menu.')
        inp = input()
        if inp == 'back':
            return
        try:
            id_, quantity = inp.split()
        except ValueError:
            continue
        status = req_sell(id_, quantity)['status']
        print('')
        print(status)
        print('')

def handle_trade():
    while True:
        print('Possible actions:')
        print('\tbuy')
        print('\tsell')
        print('\tback')
        inp = input()
        if inp == 'buy':
            handle_buy()
        elif inp == 'sell':
            handle_sell()
        elif inp == 'back':
            return

def main():
    print(req_index())

    while True:
        display_state()
        print('What do you want to do?')
        display_actions()
        inp = input()
        if inp == 'trade':
            handle_trade()
        elif inp == 'travel':
            req_travel()
        elif inp == 'reset':
            print('Are you sure you want to reset? Enter "yes" if so.')
            inp = input()
            if inp == 'yes':
                req_reset()
        elif inp == 'quit':
            sys.exit()

if __name__ == '__main__':
    main()

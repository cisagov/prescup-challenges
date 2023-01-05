#!/usr/bin/python3

from buy import AutoBuy

username = 'admin'
password = 'AncientMariner99'

def main():
    ab = AutoBuy( username, password )
    bph = { 'id': 1 }
    bnd = { 'id': 2 }

    phatBought = ab.didBuy( 'kowalski', bph )
    bndBought = ab.didBuy( 'kowalski', bnd )

    if phatBought:
        print( 'BluePartyHat: Success' )
    else:
        print( 'BluePartyHat: Failure' )

    if bndBought:
        print( 'Bandanna: Success' )
    else:
        print( 'Bandanna: Failure' )


if __name__ == '__main__':
    main();

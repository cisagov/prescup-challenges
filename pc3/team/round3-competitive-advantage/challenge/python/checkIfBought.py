#!/usr/bin/python3

from buy import AutoBuy

username = 'admin'
password = 'AncientMariner99'

def main():
    ab = AutoBuy( username, password )
    print( 'Check Purchases' )
    bph = { 'id': 1 }
    bnd = { 'id': 2 }

    print( 'blue party hat',  ab.didBuy( 'kowalski', bph ) )
    print( 'bandanna', ab.didBuy( 'kowalski', bnd ) )

    print( 'blue party hat',  ab.didBuy( 'cortex', bph ) )
    print( 'bandanna', ab.didBuy( 'cortex', bnd ) )

if __name__ == '__main__':
    main();

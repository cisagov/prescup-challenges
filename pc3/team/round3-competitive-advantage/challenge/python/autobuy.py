#!./python3

from buy import AutoBuy
import time

username = 'cortex'
password = 'vortex'

def main():
    ab = AutoBuy( username, password )
    print( 'Auto Buy' )

    items = []
    itemA = { 'id': 1, 'name': 'Blue Party Hat', 'price': '9999.99', 'quantity': 1 }
    itemB = { 'id': 2, 'name': 'Bandanna', 'price': '9999.98', 'quantity': 1 }
    items.append( itemA )
    items.append( itemB )

    n = 0
    while True:
        print( "Buying, iteration " + str( n ) )
        n = n + 1
        ab.addToCart( items )
        ab.checkout()
        time.sleep( 4 )

if __name__ == '__main__':
    main();

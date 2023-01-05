#!./python3

from buy import AutoBuy
import time
import random

username = 'admin'
password = 'AncientMariner99'

def main():
    ab = AutoBuy( username, password )
    print( 'Auto Stock' )

    phat = { 'id': 1 }
    bnd = { 'id': 2 }

    n = 0
    while True:
        print( "Stocking, iteration " + str( n ) )
        n = n + 1
        ab.addStock( phat, 1 )
        time.sleep( 60 + random.randint( 20, 90 ) )

if __name__ == '__main__':
    main();

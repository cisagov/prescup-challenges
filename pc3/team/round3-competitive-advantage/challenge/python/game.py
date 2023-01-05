#!/usr/bin/python3

import time
import random
from buy import AutoBuy

username = 'admin'
password = 'AncientMariner99'

def main():
    ab = AutoBuy( username, password )
    print( 'Running the game.' )
    bph = { 'id': 1 }
    bnd = { 'id': 2 }

    hardState = False
    n = 0
    while True:
        print( "Game iteration " + str( n ) )
        n = n + 1
        gotPhat = ab.didBuy( 'kowalski', bph )
        if not gotPhat:
            ab.addStock( bph, 1 )
        else:
            if not hardState:
                ab.setMode( 'HARD' )
                hardState = True
            ab.addStock( bnd, 1 )
        time.sleep( 60 + random.randint( 20, 90 ) )


if __name__ == '__main__':
    main();

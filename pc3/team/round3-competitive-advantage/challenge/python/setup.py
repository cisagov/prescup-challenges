#!./python3

from buy import AutoBuy
from os.path import exists

username = 'admin'
password = 'AncientMariner99'

def main():
    ab = AutoBuy( username, password )
    print( "Setup e-commerce site!!" )
    bph      = ab.createItem( 'Blue Party Hat', '10.00', '9999.99', 'A festive hat.' )
    bandanna = ab.createItem( 'Bandanna', '10.00', '9999.98', 'Infinite' )

    potion = ab.createItem( 'Potion', '1.00', '50.00', 'Restores a small amount of HP.' )
    ether = ab.createItem( 'Ether', '1.00', '200.00', 'Restores MP.' )
    elixir = ab.createItem( 'Elixir', '1.00', '1000.00', 'Fully restores HP and MP.' )

    moog = ab.createItem( 'Moog 234', '1.00', '12.00', 'U-joint for front and rear driveshafts.' )
    timken = ab.createItem( 'Timken 8622', '1.00', '15.00', 'Front pinion seal.' )


    print( ab.addStock( potion, 100 ) )
    print( ab.addStock( ether, 50 ) )
    print( ab.addStock( elixir, 13 ) )
    print( ab.addStock( moog, 4 ) )
    print( ab.addStock( timken, 2 ) )



if __name__ == '__main__':
    if exists( '/home/student/.pcsetup' ):
        print( '/home/student/.pcsetup exists. not running setup.' )
        exit()
    f = open( '/home/student/.pcsetup', 'a' )
    f.write( 'delete me to re-run setup' )
    f.close()
    print( "running" )
    main();

This challenge is only partially open sourced. The files in the challenge directory are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

Wholesaler
- Create an Ubuntu Linux web server
- Install mysql
- Use the included [database-schema.sql](database-schema.sql) to create the database

The wholesaler web site is delivered by the [ecommerce-web-app]ecommerce-web-app.jar) JAVA application. The [source code](ecommerce-web-app) for [this JAR](ecommerce-web-app.jar) is included.
You will need to compile and run the provided source code in order to run the ecommerce application. 

You will also need to run the [wrapgame.sh](python/wrapgame.sh) script to operate the challenge after the ecommerce site is available. This script sets up and runs the challenge by calling [setup.py](python/setup.py) once, [wrapbuy.sh](python/wrapbuy.sh) once and [game.py](python/game.py) continuously.

There is also a python directory on Wholesaler that contains:
- [autobuy.py](python/autobuy.py) - The adversary that the player has to beat. autobuy.py buys the hard-to-get stuff within seconds of it being added to inventory

- [buy.py](python/buy.py) - buy.py is a small library with a bunch of functions that simplify posting data to the server

- [game.py](python/game.py) - game.py logs in and periodically adds a party hat or bandana to the current stock, then sleeps for a random amount of time. It also changes the state from easy to hard once the party hat is purchased.

- [setup.py](python/setup.py) - setup.py creates inventory and adds initial item stocks for the player to buy

- [wrapbuy.sh](python/wrapbuy.sh) - wrapbuy.sh runs autobuy.py over and over, which is the adversary that the player has to beat.

- [wrapgame.sh](python/wrapgame.sh) - Called by t25scripts.service. Sets up and runs the challenge by calling setup.py once, wrapbuy.sh once and game.py continuously.

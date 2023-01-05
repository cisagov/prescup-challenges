# T25 Competitive Advantage Solution Guide

## Behind the Scenes

- Inventory is added a brief random intervals, approximately every 90-120 seconds
- One Blue Party Hat is added at a time until the participant successfully buys one
- Buying a Blue Party Hat triggers several changes:
  - the server goes into "Hard Mode"
  - Blue Party Hats it will no longer be available to purchase
  - one Bandanna will be available to purchase at random intervals (approximately every 90-120 seconds)
- There is a user running a script every 3 seconds that buys up the desired items if they are in stock. It should not be possible to buy a Blue Party Hat or Bandanna using the browser
- "Hard Mode" means the server checks for the presence of User-agent and Referrer headers in the HTTP requests. No headers, no service. Most people who write a script will probably disregard these fields and then wonder why the script worked for the Blue Party Hat but quit working for the Bandanna. Lol.

## Important Notes

QA Testers: Please ensure that it isn't possible to buy the Blue Party Hat using the browser. If the participants figure out a way to do this quickly, they won't be forced to write a script and the second "hard" part won't be any more challenging.

## Solution

The only (intended) way to beat the guy with the bot is to write your own bot and run it faster. The bot you're playing against is deliberately slowed down to 3 seconds per attempt to checkout, so an unbounded script should easily beat it.

### Script
Python programs for a solution are provided in this directory. 

Run [autobuy.py](autobuy.py) and within a few minutes you should have both key items.

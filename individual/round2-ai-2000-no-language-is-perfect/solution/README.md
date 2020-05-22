<img src="../../../logo.png" height="250px">

# No Language is Perfect

## Solution

It is assumed that you have already attempted to solve the challenge and have a basic idea of how the game works.

### Following the code path

First, let's look in `gameclient.py`. This is how we interact with the server, so it's natural we start here.
It's immediately evident that all checking is done on the server side, and that this client is only making HTTP
requests on the player's behalf.

Let's follow the code path to buy the challenge flag. In the client menu, we select "trade" and then "buy, so we end up
in the function `handle_buy` in which we're asked to specify the item ID and the number we want to buy. Entering `5 1`
here indicates that you want to purchase one copy of the challenge flag, and the program calls the `req_buy` function
with `id_ = 5` and `quantity = 1`. Further following these calls, we see that an HTTP GET request is formed with the
path `buy/{item_id}/{quantity}`, or `buy/5/1` in our example.

Now let's look at `server.rs`. We want to first look at whatever function is being called when the server receives our
HTTP GET request. On line 383 of the server code, we see `#[get("/buy/<item_id>/<quantity>")]` which should look
familiar. A few lines down we see the variable `buy_result` being assigned from the `match` expression, which is just
checking if the given item ID was valid. On success, the `game_state.buy_items(good, quantity)` function is called.

The `buy_items` function is on line 152. Looking at lines 156-158, you may think that if you just enter 0 for the
quantity of flags, you win. You can easily verify that this isn't correct, and the reason will become apparent soon.

Line 169 is very important. This is an unchecked multiplication of the cost with the quantity given by the client. By
default, Rust will only check for overflows when built in debug mode. In release mode, the value will just wrap around.
We will revisit this just as soon as we finish tracing the code path.

Finishing the code path trace, the next `match` expression checks on the item ID. We entered the challenge flag ID, so
if we can pass the cost check, the function returns the `FlagPurchased` enum value. To confirm this, let's go back to
the `buy` function on line 384. In the second `match` expression in this function, we can see that if the `buy_result`
variable is `FlagPurchased`, then the `retrieve_flag()` function is called, which actually opens the flag file and
retrieves its contents to return to the client as a status. This is why entering 0 for the quantity would not work -
getting the server to return the flag is not `Success`, it's `FlagPurchased`.

### Finding a solution

We aren't done yet. We will need to actually find a solution that works. We could try writing a script that just
repeatedly submits requests to the server and this will eventually work - but not quickly. However, there's a much
better way to solve this challenge.

If we can overflow the multiplication on line 169 such that `total_cost` is tiny, we can pass the check. To get
`total_cost` to roll over to 0, we need the two factors to multiply to some multiple of 2<sup>64</sup>.
The first thing you would probably try is to enter 2<sup>64</sup> for the quantity of challenge flags, because the
multiplication product of any two numbers are by definition a multiple of those two numbers. You would have gotten away
with it, if it weren't for ~~those meddling kids~~ the fact that quantity is also limited to an unsigned 64-bit int.
When you try it, you get an error.

Of course, we don't need any particular multiple of 2<sup>64</sup>. Any will suffice, as long as it can be a product of
the cost, 10<sup>18</sup> and some unknown number that we need to find. Let's just choose the **lowest
common multiple** for the sake of this example. We can find it using the formula `a * b / gcd(a, b)` (**greatest common
divisor**). We need to find a common multiple of the `cost` and 2<sup>64</sup> (these are what we have right now). This
gives us a very large number - `70368744177664000000000000000000`. We're almost there.

Finally, in order to find what we should submit for our challenge flag quantity, notice that we found the lowest
common multiple of one known number and the **modulus**, 2<sup>64</sup> of our range. We have one factor to construct
this common multiple, 10<sup>18</sup>. We can divide the common multiple we found by the (`cost`), 10<sup>18</sup> to
get what we should submit as our quantity (`number`). The result is `70368744177664`.

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.
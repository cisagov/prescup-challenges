# No Language Is Perfect Vol. II: More Fun With Numbers Solution

On line 172 of [oldsource.rs](../challenge/oldsource.rs) is the calculation `let total_cost = number * cost;`. As mentioned in the challenge description, the comment above this line suggests that this is a possible attack vector. As also mentioned in the description, the `number` variable comes from the `buy` call's `number` value, meaning that the player controls this value.

Through experimenting with the bounds of the server's accepted input, we can determine that one of the changes made in the "live" version of the server is that the `/buy/<item_id>/<number>` endpoint accepts an unsigned **128-bit** integer value for the `number` variable, instead of the 64-bit value that it had accepted in the old version (as shown in the [oldsource.rs](../challenge/oldsource.rs) file).

The trivial solution would be to try 0 or 2^128, but the challenge foils these values. 0 is rejected in the code, while attempting to send 2^128 will return a 404 error from the server (because of the bounds-checking done by the server). This means we need to think about our solution a bit.

Further experimentation reveals that each time the server's `buy` endpoint is called, the challenge flag cost changes. From sampling the possible values, the only clear pattern that seems to emerge is that the values are always **even** values. (See line 124 of [main.rs](source/src/main.rs) for the implementation).

This challenge must be solved by overflowing the `total_cost` result to be 0 so that the starting money is enough to win. To overflow an integer to exactly 0 when we control one of the variables, we need to ensure that `number * cost` is a multiple of the **modulus**, which is 2^128 in this case (because all of the numbers are unsigned 128-bit integers).

* Since `cost_per_unit = 2 * r` for some random value `r`, `total_cost = number * cost_per_unit` or just `total_cost = number * 2 * r`.
* This calculation must produce any multiple of 2^128, so define the equality `f * 2^128 = number * 2 * r` for some factor `f`.
* Rearrange it: `f/r * 2^128 = number * 2`.
* Factor out the 2: `f/r * 2^127 = number`.
* `f` is an arbitrary factor in the equation because of the integer-wrapping, so set `f = r`, which makes the `f/r` term equal 1, leaving us with `2^127 = number`.

If we do an HTTP request to the server using this number (in its full form, `170141183460469231731687303715884105728`), we get the flag with a very short `curl` command: `curl localhost:8000/buy/5/170141183460469231731687303715884105728`.

### Submission

```
5a65f5c9bf8c2628
```

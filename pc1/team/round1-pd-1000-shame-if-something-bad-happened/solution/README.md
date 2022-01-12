<img src="../../../pc1-logo.png" height="250px">

# Nice files. Would be a shame if something were to happen to them...

## Solution

This solution will not be a full walkthrough of solving the challenge. The `source.rs` and `team-round1.pdb` files will
be a lot more valuable than a written guide.

### Stage 1 parse.unwrap()

The easiest way to get through stage 1 is to NOP the unwrap call after the parse.

### Stage 4 "Invalid Padding"

There is a timer check hidden in the decrypt function. See lines 230-236 of `source.rs`.

## License
Copyright 2020 Carnegie Mellon University.  
Released under a MIT (SEI)-style license, please see LICENSE.md in the project root or contact permission@sei.cmu.edu for full terms.

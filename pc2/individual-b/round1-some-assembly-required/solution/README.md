# Some Assembly Required Solution

There are many valid solutions for this challenge. The hard(ish) way to solve the challenge is to find instructions with
at least one other equivalent instruction and replacing the original with an equivalent. This can, for example, mean
replacing an `xor eax, eax` instruction with `mov eax, 0` and this will remain a valid executable.

However, a simpler approach is to insert `nop` instructions between existing instructions. As the signature detection in
this challenge is rudimentary, it searches only for the exact arrays of bytes that it expects to find. So adding `nop`
instructions in between existing instructions will break some of those signatures. It's only a matter of adding enough
of them to pass the bar for the challenge.

It should also be noted that the server does not actually run the program, creating a potential loophole where any
arbitrary (valid) instructions can be used to split signatures and it will be valid. As the simple approach to the
challenge is to just add `nop` instructions between existing instructions, this loophole doesn't give any advantage over
doing that approach.

### Submission

```
e631f3d34ea24c29
```


<img src="../../../logo.png" height="250px">

# + Integer * Overflow >>

## Solution

On line 93 of `file1.c` is the line `max_loops = cpu_khz << 10 - (ntsc - tsc);`. You would need to do some searching
to find that this code is from the Linux Kernel, where this line was patched in
[this commit](https://github.com/torvalds/linux/commit/ea136a112d89bade596314a1ae49f748902f4727)
to cast the `cpu_khz` variable to `long long` to avoid an overflow from the bit-shift operation. To confirm this bug,
you could find the definition of this variable
[here](https://github.com/torvalds/linux/blob/master/arch/x86/kernel/tsc.c#L32) where it's defined as an `unsigned int`.

On line 48 of `file2.c` is the line
`umem = ib_umem_get(context, ucmd.buf_addr, ucmd.cqe_size * entries, IB_ACCESS_LOCAL_WRITE, 1);`. Searching for this
line would reveal that this line was patched in
[this commit](https://github.com/torvalds/linux/commit/28e9091e3119933c38933cb8fc48d5618eb784c8). A user could enter a
large number for this value and cause an integer overflow.

Flag - `93_48`

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.
# We Don't Need No Water Solution

## 1. Reverse-engineering the exploit

There are several versions of the exploit, compiled for different architectures
with different optimization levels. Probably the one easiest to interpret is
`gen_vuln1.aarch64.elf`. After importing it into Ghidra, we find its `main()`
function, which looks something like this:

```c
/* WARNING: Type propagation algorithm not settling */

undefined8 main(int param_1,undefined8 *param_2)

{
  int iVar1;
  undefined8 uVar2;
  char acStack80 [40];
  char local_28;
  char local_19;
  longlong *local_18;
  int *local_10;
  short *local_8;

  local_8 = (short *)&local_28;
  local_10 = (int *)&local_28;
  local_18 = &local_28;
  if (param_1 == 2) {
    getrandom(&local_28,0x10,0);
    iVar1 = atoi((char *)param_2[1]);
    if (iVar1 == 4) {
      *local_18 = -local_18[1];
    }
    else {
      if (iVar1 < 5) {
        if (iVar1 == 3) {
          *local_10 = -local_10[3];
        }
        else {
          if (iVar1 < 4) {
            if (iVar1 == 1) {
              local_28 = -local_19;
            }
            else {
              if (iVar1 == 2) {
                *local_8 = -local_8[7];
              }
            }
          }
        }
      }
    }
    b2str(&local_28,acStack80);
    puts(acStack80);
    uVar2 = 0;
  }
  else {
    fprintf(stderr,"Usage: %s mode\n",*param_2);
    uVar2 = 0xffffffff;
  }
  return uVar2;
}
```

We can tell that `param_1` is actually `argc`, and `param_2` is really `argv`,
and, as such, `iVar1 = atoi(argv[1])`. Therefore `iVar1` is really the selector
for which of the four types of exploit one might wish to generate. This is
further confirmed by having `iVar1` compared to `1`, `2`, `3`, and `4`.

Long story short, the code fragment above generates a random buffer of 16 bytes
in size, then, based on the mode of exploit, ensures that the first and last
8-bit byte, 16-bit word, 32-bit dword, or 64-bit quad will be complementary of
each other, or, in other words, add up to 0. These are the four ways in which
a request string (in the form of a 32-character hex representation of our 16
bytes) would cause the server to fail.

If we manually generate a "mode 1" exploit (where the first and last bytes are
complementary), and send it to the server, we get:

```bash
echo -n '00112233445566778899aabbccddee00' | nc svcnat 31337
FAIL
Ncat: Connection reset by peer.
```

Notice how the first and last byte were both set to `00` (the easiest way to
have them add up to 0!).

## 2. Writing a userspace firewal rule

With `Documents/user_filter.c`, we're already given all the necessary building
blocks for writing a userspace firewall rule that works in conjunction with the
`netfilter_queue` library. Inspecting the existing firewall rules on `svcnat`,
we see:

```bash
sudo iptables-save
*filter
...
-A FORWARD -p tcp -m tcp --dport 31337 -j NFQUEUE --queue-num 0 --queue-bypass
...
*nat
...
-A PREROUTING -i ens32 -p tcp -m tcp --dport 31337 -j DNAT --to-destination 192.168.3.254:31337
...
```

In other words, requests to port 31337 on the "public" interface of `svcnat`
are forwarded over a private link to the actual server at `192.168.3.254`.
Also, TCP traffic to port 31337 is queued for a userspace decision, to be
made when a program such as `user_filter` is in execution on `svcnat`.

We now have to modify the `tcp_payload_verdict()` function to return a value
of `NF_DROP` when the 32-character request matches one of the exploit modes
we learned about in Step 1 above, and `NF_ACCEPT` for all other candidate
packets. The new `tcp_payload_verdict()` might look something like this:

```c
/* a 128 bit data structure consisting of either 8, 16, 32, or 64 bit chunks;
 */
typedef union {
	uint8_t b[16];
	uint16_t w[8];
	uint32_t d[4];
	uint64_t q[2];
} __attribute__((packed, aligned(8))) bitstring_u_t;

/* expect str to be at least 32 characters long;
 * return 0 if buf was hex and successfully converted;
 * return -1 otherwise;
 */
int str2bsut(const uint8_t *str, bitstring_u_t *bsut)
{
	int i;
	char buf[3];
	for (i = 0; i < 16; i++) {
		buf[0] = *str++;
		buf[1] = *str++;
		buf[2] = 0;
		if (!(isxdigit(buf[0]) && isxdigit(buf[1]))) {
			return -1;
		}
		bsut->b[i] = strtol(buf, NULL, 0x10);
	}
	return 0;
}

/* expect a non-NULL bsut pointer;
 * return code matching "vulnerability";
 * return 0 if not "vulnerable";
 */
int bsut_verify(bitstring_u_t *bsut)
{
	if ((uint64_t)(bsut->q[0] + bsut->q[1]) == 0) {
		return 4;
	}
	if ((uint32_t)(bsut->d[0] + bsut->d[3]) == 0) {
		return 3;
	}
	if ((uint16_t)(bsut->w[0] + bsut->w[7]) == 0) {
		return 2;
	}
	if ((uint8_t)(bsut->b[0] + bsut->b[15]) == 0) {
		return 1;
	}
	return 0;
}

uint32_t tcp_payload_verdict(const uint8_t *buf)
{
	bitstring_u_t bsut;
	uint8_t c;
	uint32_t i;
	for (i = 0; i < 32; i++) {
		c = buf[i];
		printf("%c", isprint(c) ? c : '.');
	}
	if (str2bsut(buf, &bsut) == 0 && bsut_verify(&bsut) != 0) {
		printf(" - drop\n");
		return NF_DROP;
	}
	printf(" - accept\n");
	return NF_ACCEPT;
}
```

After recompiling `user_filter` to reflect these changes, we copy it over to
`svcnat` (e.g., using `scp`), and run it there as root:

```bash
sudo user_filter
```

At this point, asking the grader at `http://challenge.us` to grade the
challenge will get us all four expected tokens.

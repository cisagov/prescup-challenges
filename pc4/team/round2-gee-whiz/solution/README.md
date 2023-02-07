# Gee Whiz

_Solution Guide_

## Overview

In the rush to retrofit the *Dauntless* with CubeDrive technology, there was a slight oversight: the drive is capable of generating accelerations much in excess of what any human crew member could survive.

Your mission is to place a firewall rule in front of the drive controller's network interface, with the goal of preventing drive commands that request acceleration values in excess of specified human-survivable limits.

The document specifying the exact ordering of the fields in the data structure representing a drive command was also misplaced, but no worries, we can provide a binary program used to convert numeric values on the command line into the requisite hex string that can be sent to the drive controller over the network.

## Questions 1-5

_Gee Whiz_ is an infinity-style challenge—a random solution is generated during challenge deployment. Notice that this solution guide is organized a little differently than other solution guides you may have read. This is because participants will complete these tasks prior to requesting all five submission tokens from http://challenge.us. Successfully completing _Gee Whiz_ and generating the five tokens entails:
- reverse-engineering a binary to gain understanding of its internal workings; 
- examining a sample source code firewall rule;
- modifying code for requests to ensure they pass the safety criteria; and
- compiling and executing a sample filter program

## Reverse-engineering the sample binary

Grab the binary from `http://challenge.us/files/drvctl.bin`. It would have been nice if you could simply run it and see which fields get modified by tinkering with the command line arguments. Alas, it's not an `x86_64` binary. Rather:

```
$ file drvctl.bin
drvctl.bin: ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, ...
```

Your next move is to import it into Ghidra. After opening and analyzing the binary, you'll run across a function similar to this:

```
undefined8 FUN_00010730(float *param_1,float *param_2)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined8 uVar5;
  float fVar6;
  
  fVar1 = *param_1;
  fVar2 = param_1[2];
  fVar3 = param_1[3];
  fVar4 = param_1[1];
  fVar6 = fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3;
  sqrtf(SUB84(param_1,0));
  *param_2 = fVar6;
  if (fVar4 == 0.0) {
    uVar5 = 0;
  }
  else if ((fVar4 == 0.0) ||
          ((((ABS(fVar1) <= 6.0 && (ABS(fVar2) <= 6.0)) && (-1.5 <= fVar3)) &&
           ((fVar3 <= 3.0 && (*param_2 <= 8.0)))))) {
    if (((uint)fVar4 < 0x1d4c1) ||
       (((ABS(fVar1) <= 3.0 && (ABS(fVar2) <= 3.0)) &&
        ((-1.0 <= fVar3 && ((fVar3 <= 2.5 && (*param_2 <= 4.0)))))))) {
      if (((uint)fVar4 < 0x36ee81) ||
         ((((ABS(fVar1) <= 2.0 && (ABS(fVar2) <= 2.0)) && (-0.5 <= fVar3)) &&
          ((fVar3 <= 2.0 && (*param_2 <= 2.5)))))) {
        uVar5 = 0;
      }
      else {
        uVar5 = 0xffffffffffffffdf;
      }
    }
    else {
      uVar5 = 0xffffffffffffffdf;
    }
  }
  else {
    uVar5 = 0xffffffffffffffdf;
  }
  return uVar5;
}
```

The fact that `fVar1` through `fVar4` are placed consecutively in memory, starting at the address of `float *param_1`, leads you to assume they must be the fields `gx`, `gy`, `gz`, and (improperly typed as `float`) `ms`.

Furthermore, the comparisons `ABS(fVar[1,2]) <= 6.0` hint at `fVar1` and `fVar2` being either `gx` or `gy` (the two behave identically as far as imposed limits and are therefore interchangeable). The comparison to `-1.5` indicates that, in this particular variant of the challenge, the `gz` parameter is `fVar3`. This leaves `fvar4` to represent the `unsigned ms` field.

Going back to how `fVar[1..4]` are ordered in memory, it can be inferred that the internal ordering of `struct drv_ctl_t` is (in this variant):

```
struct drv_ctl_t {
        float gx;     /* fVar1 = *param_1 */
        unsigned ms;  /* fVar4 = param_1[1] */
        float gy;     /* fVar2 = param_1[2] */
        float gz;     /* fVar3 = param_1[3] */
};
```

An ascii request sent through the firewall to the drive computer would represent:

```
String: d3b07384d113edec49eaa6238ad5ff00
Legend: <------><------><------><------>
           gx      ms      gy      gz
```

## Writing a userspace firewall rule

Download the sample userspace firewall filter program from: `http://challenge.us/files/sample_filter.c`. This program already provides the necessary building blocks for writing a userspace firewall rule that works in conjunction with the `netfilter_queue` library. Inspecting the existing firewall rules on `svcnat`, you see:

```
$ sudo iptables-save
*filter
...
-A FORWARD -p tcp -m tcp --dport 31337 -j NFQUEUE --queue-num 0 --queue-bypass
...
*nat
...
-A PREROUTING -i ens32 -p tcp -m tcp --dport 31337 -j DNAT --to-destination 192.168.4.254:31337
...
```

Requests to port 31337 on the "public" interface of `svcnat` are forwarded over a private link to the actual server at `192.168.4.254`. Also, TCP traffic to port 31337 is queued for a userspace decision, to be made when a program such as `sample_filter` is in execution on `svcnat`.

You now have to modify the `tcp_payload_verdict()` function to return a value of `NF_DROP` when the 32-character request would exceed the specified acceleration and time limits, and `NF_ACCEPT` for requests passing the safety criteria. The new filter program might look something like what is provided. You will need to re-order the fields of `struct {...} ctl` according to what you found in Ghidra.

```
/* user_filter.c -- userspace filtering of specific tcp payloads
 *
 * ensure traffic is sent to userspace by netfilter rule, e.g.:
 *     iptables -A FORWARD -p tcp --dport 31337 -j NFQUEUE --queue-num 0 \
 *             [--queue-bypass]
 *
 * compile with:
 *     gcc -o user_filter user_filter.c -Wall -lm -lnetfilter_queue
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <error.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <math.h>

/* a 128 bit drive control data structure
   NOTE: the exact field ordering is variant specific!!!
 */
typedef union {
    struct {
        float gx;
        unsigned ms;
        float gy;
        float gz;
    } ctl;
    unsigned char buf[16];
} __attribute__((packed, aligned(8))) drvctl_t;

/* expect str to be at least 32 characters long;
 * return 0 if buf was hex and successfully converted;
 * return -1 otherwise;
 */
int str2drvctl(const uint8_t *str, drvctl_t *d)
{
    int i;
    char bt[3];
    for (i = 0; i < 16; i++) {
        bt[0] = *str++;
        bt[1] = *str++;
        bt[2] = 0;
        if (!(isxdigit(bt[0]) && isxdigit(bt[1]))) {
            return -1;
        }
        d->buf[i] = strtol(bt, NULL, 0x10);
    }
    return 0;
}

/* expect a non-NULL drvctl pointer;
 * return -1 if g force exceeds limits
 * return 0 if nominal;
 */
static int check_drvctl(drvctl_t *d)
{
    float gx = d->ctl.gx, gy = d->ctl.gy, gz = d->ctl.gz;
    float gt = sqrtf(gx * gx + gy * gy + gz * gz);
    unsigned ms = d->ctl.ms;

    /* 0 duration means it's a test comand, drive not engaged */
    if (ms == 0)
        return 0;

    /* g limits for any non-zero length of time */
    if (ms > 0 && (fabsf(gx) > 6.0 || fabsf(gy) > 6.0 ||
            gz < -1.5 || gz > 3.0 || gt > 8.0))
        return -1;

    /* g limits for up to 120s (2m) */
    if (ms > 120000 && (fabsf(gx) > 3.0 || fabsf(gy) > 3.0 ||
            gz < -1.0 || gz > 2.5 || gt > 4.0))
        return -1;

    /* g limits for up to 3600s (1h) */
    if (ms > 3600000 && (fabsf(gx) > 2.0 || fabsf(gy) > 2.0 ||
            gz < -0.5 || gz > 2.0 || gt > 2.5))
        return -1;

    /* all checks passed, drive command survivable by human crew */
    return 0;
}

uint32_t tcp_payload_verdict(const uint8_t *buf)
{
    drvctl_t d;
    uint8_t c;
    uint32_t i;
    for (i = 0; i < 32; i++) {
        c = buf[i];
        printf("%c", isprint(c) ? c : '.');
    }
    if (str2drvctl(buf, &d) == 0 && check_drvctl(&d) != 0) {
        printf(" - drop\n");
        return NF_DROP;
    }
    printf(" - accept\n");
    return NF_ACCEPT;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t id, verdict;
    uint8_t *p_data;
    int p_len;

    p_len = nfq_get_payload(nfad, &p_data);
    if (p_len < 0)
        return p_len;

    verdict = NF_ACCEPT;

    /* tcp data starts at offset 52;
     * we are interested in scanning 32 characters:
     */
    if (p_len >= 84)
        verdict = tcp_payload_verdict(p_data + 52);

    ph = nfq_get_msg_packet_hdr(nfad);
    id = ntohl(ph->packet_id);
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int main(int argc, char *argv[])
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int rv, fd;
    char buf[0x1000] __attribute__ ((aligned));

    /* setup: */
    h = nfq_open();
    if (h == NULL)
        error(1, 0, "nfq_open() error\n");
    rv = nfq_bind_pf(h, AF_INET);
    if (rv < 0)
        error(1, 0, "nfq_bind_pf() error\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (qh == NULL)
        error(1, 0, "nfq_create_queue() error\n");
    rv = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    if (rv < 0)
        error(1, 0, "nfq_set_mode() error\n");
    fd = nfq_fd(h);

    /* main loop: */
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
        if (nfq_handle_packet(h, buf, rv) != 0)
            break;

    /* teardown: */
    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}

```

After recompiling `sample_filter` to reflect these changes:

```
gcc -o drvctl_filter sample_filter.c -Wall -lnetfilter_queue -lm
```

... copy it over to `svcnat` (e.g., using `scp`), and run it there as root:

```
$ sudo drvctl_filter
```

## Grading

Go to `http://challenge.us` to generate the five tokens needed to successfully complete this challenge.

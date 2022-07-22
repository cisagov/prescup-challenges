# Hard Bass & Kvass Solution

We're looking for exfiltrated data in a pcap file. Opening it up in Wireshark,
it looks like a lot of tcp/443 traffic. One of the hints in the description
indicates that IPv6 may play a role, so we filter for it:

```
ipv6.version == 6
```

We notice a bunch of TCP sessions with 77 byte data payloads being sent out of
the target network enclave. The last such payload looks like this (***NOTE***:
This is only an example, your challenge was instantiated with a different,
randomly generated password):

```
MC4gVGhlIGFkbWluIHBhc3N3ZCBpcyA4NjQ4MzdiNDk4MmFiYzVlN2YyZDQzNmVlNjNmYTllYQo=
```

Running this through `base64 -d`, we get:

```
0. The admin passwd is 864837b4982abc5e7f2d436ee63fa9ea
```

That's our first flag, worth 20% of the total challenge value!

To recover the entire file (so we can calculate its `md5sum` -- our second
flag), we must reassemble all the 77-byte fragments. Putting them all together,
we get:

```
MS4gUG91ciAxLjVMICg1MG96KSB3YXRlciBpbnRvIGEgcG90LCBicmluZyB0byBib2lsCgoyLiBU
cmsnCgozLiBXYXNoIGhhbGYgb2YgMS8zIGN1cCBvZiByYWlzaW5zLCBhbmQgb25lIGxlbW9uCgo0
LiBNb3ZlIHBvdCBvZmYgdGhlIGhlYXQsIHRoZW4gYWRkOgogICAgIC0gcmFpc2lucywgdG9hc3Qs
dmUgY2h1bmtzLCBzdHJhaW4gbGlxdWlkIGludG8gZnJlc2ggcG90LCB0aGVuIGFkZDoKICAgLSBz
YXIKICAgLSBvbmUgdHNwLiBkcnkgeWVhc3QKCjcuIFBvdXIgaW50byBtYXNvbiBqYXIgYW5kIGxl
Z2UpCgo4LiBTdHJhaW4gdGhyb3VnaCBjaGVlc2UgY2xvdGgsIGNvZmZlZSBmaWx0ZXIsIG9yIGNs
ZWFuIHRvd2VsCiAgIGludG8gc2Vjb25kIG1hc29uIGphcgoKOS4gU3F1ZWV6ZSBzZWNvbmQgaGFs
ZiBsZW1vbiBpbnRvIGphciwKICAgdGhlbiByZWZyaWdlcmF0ZSBiZWZvcmUgZHJpbmtpbmcuCgox
MC4gVGhlIGFkbWluIHBhc3N3ZCBpcyA4NjQ4MzdiNDk4MmFiYzVlN2YyZDQzNmVlNjNmYTllYQo=
```

which, once decoded, yields an obviously truncated file. What might be the
missing pieces?

If we apply a new filter, on the size of the tcp payload:

```
data.len == 77
```

we notice that some of the base64-encoded chunks are sent out via ipv4 (in
addition to the ones sent out using IPv6). If we extract those chunks as well
(in the order in which they were sent out), we get:

```
MS4gUG91ciAxLjVMICg1MG96KSB3YXRlciBpbnRvIGEgcG90LCBicmluZyB0byBib2lsCgoyLiBU
b2FzdCB0d28gc2xpY2VzIG9mIGJsYWNrIHJ5ZSBvciBwdW1wZXJuaWNrZWwgYnJlYWQgb24gJ2Rh
cmsnCgozLiBXYXNoIGhhbGYgb2YgMS8zIGN1cCBvZiByYWlzaW5zLCBhbmQgb25lIGxlbW9uCgo0
LiBNb3ZlIHBvdCBvZmYgdGhlIGhlYXQsIHRoZW4gYWRkOgogICAgIC0gcmFpc2lucywgdG9hc3Qs
IGhhbGYgdGhlIGxlbW9uIChzbGljZWQpCgo1LiBMZXQgc2l0IGZvciAzIGhvdXJzCgo2LiBSZW1v
dmUgY2h1bmtzLCBzdHJhaW4gbGlxdWlkIGludG8gZnJlc2ggcG90LCB0aGVuIGFkZDoKICAgLSBz
ZWNvbmQgaGFsZiBvZiB0aGUgcmFpc2lucyAod2FzaGVkKSwKICAgLSAxMDBnICgzLjVveikgc3Vn
YXIKICAgLSBvbmUgdHNwLiBkcnkgeWVhc3QKCjcuIFBvdXIgaW50byBtYXNvbiBqYXIgYW5kIGxl
dCBzaXQgZm9yIDIgZGF5cyBpbiBhIHdhcm0gcGxhY2UKICAgKGUuZy4sIG9uIHRvcCBvZiBmcmlk
Z2UpCgo4LiBTdHJhaW4gdGhyb3VnaCBjaGVlc2UgY2xvdGgsIGNvZmZlZSBmaWx0ZXIsIG9yIGNs
ZWFuIHRvd2VsCiAgIGludG8gc2Vjb25kIG1hc29uIGphcgoKOS4gU3F1ZWV6ZSBzZWNvbmQgaGFs
ZiBsZW1vbiBpbnRvIGphciwKICAgdGhlbiByZWZyaWdlcmF0ZSBiZWZvcmUgZHJpbmtpbmcuCgox
MC4gVGhlIGFkbWluIHBhc3N3ZCBpcyA4NjQ4MzdiNDk4MmFiYzVlN2YyZDQzNmVlNjNmYTllYQo=
```

which, once decoded, gives us a complete file whose `md5sum` we can submit as
our second flag, for the rest of the challenge's 80% worth of points.

## Answer Key

|    Q     |    Flag:                           |
|----------|------------------------------------|
| password | `f2472d1dd6c061aacab3e6351d4b8a86` |
|  md5sum  | `2958643eb5efeb138355d7c3e43a3b69` |

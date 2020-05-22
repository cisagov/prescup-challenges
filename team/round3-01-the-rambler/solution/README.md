<img src="../../../../../logo.png" height="250px">

# The Rambler

This challenge is based on remote agents reporting secret messages back to a
server contained within the logs. It is based on these articles:
https://hackaday.com/2019/08/28/secret-messages-could-be-hiding-in-your-server-logs/
and
https://miscdotgeek.com/curlytp-every-web-server-is-a-dead-drop/

## Hints

1. Leon Ray Livingston refers to
[a famous hobo](https://en.wikipedia.org/wiki/Leon_Ray_Livingston) who had
several [different nicknames](https://en.wikipedia.org/wiki/Leon_Ray_Livingston#cite_note-1).
2. A review of user agents finds a few non-standard ones with the nicknames of
Leon Ray. This greatly reduces the number of records we need to work with.
3. Hobo code [glyphs](https://www.popularmechanics.com/technology/a25174860/hobo-code/)

## Solution

First, we notice that most (all?) of the log entries are HTTP calls that have
three query string arguments: i, k, and v.

The challenge description contains lots of subtle hints that the covert
communication is related to Leon Ray Livingston, a famous hobo who used several
different nicknames. These nicknames are scattered throughout the log as part
of non-standard user agent strings, which would allow competitors to identify
the relevant log entries.

Correlated with user agent strings modified to contain (portions of) Leon Ray's
nicknames, all relevant log entries have a value for their `i` argument
starting with an uppercase `Z`.

Once this has been determined (through observation), we can isolate the
relevant log entries using `grep`:

```
grep '&i=Z.\+&k=.\+&v=[^ ]\+ ' rambler_logs.log
```

The values of `k` represent different messages, whereas the corresponding `v`
values are fragments of base64-encoded message data for their corresponding
message, `k`. Exactly three (`k,v`) pairs start with `data:image/png...`, and
another three are shorter in length than thre rest. Based on this, we can
safely conclude that those pairs are the start, and, respectively, the end of
each of three distinct messages (this is supported by the fact that there are
only three distinct values for `k` within the set of relevant log entries).

The next question is in what order should we glue together the three different
messages' fragments? Looking at the start and end fragments and comparing to
the other, intermediate ones, we can immediately tell that associated log entry
timestamps are useless, and that the fragments have been transmitted
out-of-order.

After careful observation, we conclude that message fragments should be sorted
by the ascending value of the `i` field. We also discard the surrounding data,
to focus on just the (`i,k,v`) triplets of the relevant messages:

```
grep -o '&i=Z.\+&k=.\+&v=[^ ]\+ ' rambler_logs.log | sort
```

If we glue together all fragments for each key, we end up with three (very long)
strings of the form `data:image/png;base64,iVBORw0KGgoA...ErkJggg==`, which, if
pasted into the URL bar of your browser, appear as glyphs in the "hobo code".
An image search for the hobo alphabet will allow converting each glyph into a
text string: `halt`, `this is the place`, and `kind lady lives here`.

What is the right ordering of the hobo glyphs? That part is encoded in the `k`
value representing each glyph, e.g.:

```
$ echo bTE= | base64 -d
m1

$ echo bTM= | base64 -d
m3
```

Concatenating the _meaning_ of each glyph in the right order yields the string
`halt this is the place kind lady lives here`, which, base64-encoded, yields:

```
$ echo -n "halt this is the place kind lady lives here" | base64
aGFsdCB0aGlzIGlzIHRoZSBwbGFjZSBraW5kIGxhZHkgbGl2ZXMgaGVyZQ==
```

That base64-encoded string is the value of `k` in another relevant log entry:

```
grep aGFsdCB0aGlzIGlzIHRoZSBwbGFjZSBraW5kIGxhZHkgbGl2ZXMgaGVyZQ== rambler_logs.log
203.72.177.141 - - [26/Oct/2019:08:50:27 -0500] "GET categories?GB=EABT3499037170876&i=80307&k=aGFsdCB0aGlzIGlzIHRoZSBwbGFjZSBraW5kIGxhZHkgbGl2ZXMgaGVyZQ==&v=NDCwMzgnMjkiTiA3M7A0Nic0MSJX HTTP/1.0" 200 4989 "https://www.schwartz.net/blog/tags/categories/main/" Mozilla/5.0 (iPod; U; CPU iPhone OS 3_2 like Mac OS X; A-1) AppleWebKit/535.15.5 (KHTML, like Gecko) Version/4.0.5 Mobile/8B114 Safari/6535.15.5
```

Looking at the value `v` corresponding to that key, and running it through a
base64 decoder, we obtain:

```
$ echo NDCwMzgnMjkiTiA3M7A0Nic0MSJX | base64 -d
40°38'29"N 73°46'41"W
```

which is the value of the flag we are looking for!

<br><br>

Flag - `40°38'29"N 73°46'41"W`

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.
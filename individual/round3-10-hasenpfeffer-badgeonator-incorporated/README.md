<img src="../../logo.png" height="250px">

# Hasenpfeffer-Badgeonator
#### Executive Order Category: Exploit and reverse engineer

> One, two, three, four, five, six, seven, eight... Schlemiel! Schlimazel!
Hasenpfeffer Badgeonator Incorporated!

## Background
Your team has been spending a lot of time trying to figure out terrorist group
SUDSYBEAR's potential targets for cells operating on US soil. On a quarantined
laptop you've been asked to investigate, there is evidence of browsing activity
to an odd piece of SaaS software — it seems to somehow map to physical location
access for a brewery in Wisconsin. The problem is, you don't have a swipe badge
that is required in order to get in and take a further look around.

## Getting Started

**Please Note:** This challenge has been modified from its original form to work
locally on your Linux machine (e.g., Fedora or Ubuntu).

To set up the software simulating the suspicious Web server, you must begin by
installing Python 3 (we used Python 3.7.6, but ymmv).

You must also have [zbar bar code reader](http://zbar.sourceforge.net) installed
in order to utilize pyzbar! We recommend trying to install it through your
native package manager before resorting to building it from source, e.g.:

```
dnf install zbar
```

or

```
apt-get install zbar
```

Finally, use `pip3` to install the necessary dependencies for the server:

```
$ sudo pip3 install -r requirements.txt
```

Alternatively, to install only for your own unprivileged user:

```
$ pip3 install --user -r requirements.txt
```

Next, launch the server on your local host:

```
$ cd challenge
$ FLASK_APP=app.py FLASK_DEBUG=1  python3 -m flask run
```

Browse to [http://127.0.0.1:5000/](http://127.0.0.1:5000/) — you should see the
badging system and Laverne's actual badge.

You note that it contains a QR code. What is a QR code anyway?

The flag is in the form of GPS coordinates (e.g., `##°##′##′′N ##°##′##′′W`).

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.
# Cut Them Off At The Firewall

*Challenge Artifacts*

Setting up this challenge requires a webserver on one subnet and a Kali machine on another subnet with a default installation pfSense router between them.

## pfSense

pfSense should have at least two NICs: one on the `10.10.10.0/24` subnet and another on the subnet of your choice.

## Webserver

The webserver runs on IP `10.10.10.100` and listens on ports `80` and `1137` with a default Apache start page. The following is entered into the `/etc/apache2/ports.conf` file:

```
Listen 80
Listen 1337
<IfModule ssl_module>
	Listen 443
</IfModule>

<IfModule mod_gnutls.c>
	Listen 443
</IfModule>
```

## Grading Script

The grading script checks for a good port `80` response and a failed port `1137`.

[gradingscript.sh](./gradingscript.sh): This grading script checks if the webserver is inaccessible on `1137` but open on `80`.
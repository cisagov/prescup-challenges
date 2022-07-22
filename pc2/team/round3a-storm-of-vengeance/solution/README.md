# Storm of Vengeance Solution

The solution is a series of questions:

**1. What is the querystring enumeration key for the first type of attack found?**

> `id`

Viewable via `tail -f /var/log/httpd/access_log | grep ?` or grep select, look for sql attacks

**2. What does the querystring enumeration value begin with for the first type of attack found?**

> `1`

Viewable via `tail -f /var/log/httpd/access_log | grep ?` or grep select, look for sql attacks

**3. In the first attack there appears to be a non-standard token in a portion of the request, what is it?**

> `PH_279_`

Viewable via `tail -f /var/log/httpd/access_log | grep ?`, look for sql attacks

**4. In the second attack there also appears to be a non-standard token in a portion of the request, what is it?**

> `LVL9_CONJ`

Easiest way is to group 404 calls to dictionary terms in order to identify directory enumeration attack, and then look at user agent

**5. What is the name of the module that is blocking client access to directory configuration files?**

> `authz_core`

`tail -f /var/log/httpd/error_log | grep htaccess`

---

**6. All storms have consequences. There seems to be another path enumeration attack occurring periodically. Can you put it in sequence? Where does the path begin?**

> South Fork Dam

    Take array of log entries that enumerate in this fashion:

```
        NDAuMzI4MDI5MQ/LTc4LjkwOTEzMDE
```

    and order them by taking a portion (XXX) of the user agent string, base64 decoding it:

```
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/XXX (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36",
```

    providing an array of base64 values:
```
        [
            [1, NDAuMzI4MDI5MQ, LTc4LjkwOTEzMDE],
            [2, NDAuMzI3Nzc1NQ/LTc4LjkxOTU5MDc],
        ]
```
    now we can decode each to look something like:

            40.3264587, -78.9163291

    putting these into a map system such as google maps, or just looking at the first and last, we can see that we start at

            The remains of the south fork dam, which is now a history center

    and finish near the

            Johnstown Flood Museum

**7. Building on question 6, can you determine the formal name of its natural conclusion?**

> Johnstown Flood Museum

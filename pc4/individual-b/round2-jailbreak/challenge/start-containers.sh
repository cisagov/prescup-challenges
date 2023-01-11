#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

docker network create c14-net
docker run --name mongo-c14 --restart always -p 27017:27017 --net c14-net -d mongo:latest
docker run --name jailbreak --restart always -e "JAILBREAK_DROP_DATABASE=1" -e "JAILBREAK_MONGO_DSN=mongodb://mongo-c14:27017/" -p 80:8000 --net c14-net -d -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd)/flag1.txt:/app/flag1.txt -v $(pwd)/source.zip:/app/src/static/source.zip jailbreak-pc22

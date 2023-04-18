#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

KEY_FLAG="Success!"
TRAIN_FLAG="Success!"

docker network create train-job-net
docker run --name loader --restart always -p 8000:8000 -e TRAINKEY=$KEY_FLAG --net train-job-net -d c29-loader
docker run --name train --restart always -p 8001:8001 -e TRAINKEY=$KEY_FLAG -e TRAIN_FLAG=$TRAIN_FLAG --net train-job-net -d c29-train

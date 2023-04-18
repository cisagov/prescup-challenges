#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

docker kill mongo-c14
docker kill jailbreak
docker rm mongo-c14
docker rm jailbreak
docker network prune -f
docker volume prune -f

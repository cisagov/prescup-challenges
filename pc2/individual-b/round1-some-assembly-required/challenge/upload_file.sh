#!/bin/bash

cat payload | curl --data-binary @- http://localhost:8000

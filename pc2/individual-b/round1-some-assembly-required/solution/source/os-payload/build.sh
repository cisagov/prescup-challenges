#!/bin/bash

gcc -c main.c
objcopy -O binary main.o main.bin

#!/bin/bash

ruby $(dirname $(realpath $(gem which metasm)))/samples/elfencode.rb code.asm -o payload

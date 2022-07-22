#!/bin/bash

ruby $(dirname $(realpath $(gem which metasm)))/samples/disassemble.rb main.bin > code.asm

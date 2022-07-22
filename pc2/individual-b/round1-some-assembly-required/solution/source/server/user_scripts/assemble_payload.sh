#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

export RUBYLIB=/usr/share/metasploit-framework/vendor/bundle/ruby/2.5.0/gems/metasm-1.0.4/

sudo chmod +x /usr/share/metasploit-framework/vendor/bundle/ruby/2.5.0/gems/metasm-1.0.4/samples/peencode.rb
/usr/share/metasploit-framework/vendor/bundle/ruby/2.5.0/gems/metasm-1.0.4/samples/peencode.rb asm_code.asm -o payload.exe

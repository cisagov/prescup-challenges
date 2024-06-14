# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

so_file := preload_test.so

main: main.c
	gcc -shared -fPIC -ldl main.c -o $(so_file)

clean: $(so_file)
	rm $(so_file)

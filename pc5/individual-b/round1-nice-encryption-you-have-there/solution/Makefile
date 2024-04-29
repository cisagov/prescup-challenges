so_file := preload_test.so

main: main.c
	gcc -shared -fPIC -ldl main.c -o $(so_file)

clean: $(so_file)
	rm $(so_file)

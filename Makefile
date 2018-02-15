all:
	gcc -O2 -fPIE -pie -fPIC -o moviedb *.c

test: vulns.c test.c
	gcc -ggdb -fsanitize=address -o test test.c vulns.c



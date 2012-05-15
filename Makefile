PROGNAME=programm

all:
	rm -f $(PROGNAME)
	gcc -g -std=c99 -I/usr/local/include -L/usr/local/lib -lfreefare -lm -lreadline -o $(PROGNAME) mdmu.c

no-gdb:
	rm -f $(PROGNAME)
	gcc -g -std=c99 -I/usr/local/include -L/usr/local/lib -lfreefare -lm -lreadline -o $(PROGNAME) mdmu.c

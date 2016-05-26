all: netnode

test: hexdump_test

netnode: netnode.c netnode.h hexdump.o
	gcc -g -Wall -DMAIN -o netnode netnode.c hexdump.o

hexdump.o: hexdump.c hexdump.h
	gcc -g -Wall -c hexdump.c

netnode.o: netnode.c netnode.h
	gcc -g -Wall -c netnode.c

example: example.c netnode.o netnode.h
	gcc -g -Wall -o example example.c netnode.o

hexdump_test:  hexdump.c
	gcc -g -Wall -DUNIT_TEST -o hexdump_test hexdump.c

clean:
	rm -f *.o *.gch netnode example hexdump_test

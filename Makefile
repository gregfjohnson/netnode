netnode: netnode.c netnode.h hexdump.o
	gcc -g -Wall -DMAIN -o netnode netnode.c hexdump.o

hexdump.o: hexdump.c hexdump.h
	gcc -g -Wall -c hexdump.c

netnode.o: netnode.c netnode.h
	gcc -g -Wall -c netnode.c

example: example.c netnode.o netnode.h
	gcc -g -Wall -o example example.c netnode.o

clean:
	rm -f *.o *.gch netnode example

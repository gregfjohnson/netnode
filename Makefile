netnode: netnode.c netnode.h print_message.o
	gcc -g -Wall -DMAIN -o netnode netnode.c print_message.o

print_message.o: print_message.c print_message.h
	gcc -g -Wall -c print_message.c

netnode.o: netnode.c netnode.h
	gcc -g -Wall -c netnode.c

example: example.c netnode.o netnode.h
	gcc -g -Wall -o example example.c netnode.o

clean:
	rm -f *.o *.gch netnode example

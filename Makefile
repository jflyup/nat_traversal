CC = gcc
CFLAGS  = -g -Wall

all:  nat_traversal

nat_traversal:  main.o nat_traversal.o nat_type.o 
	$(CC) $(CFLAGS) -o nat_traversal main.o nat_traversal.o nat_type.o -pthread

main.o:  main.c
	$(CC) $(CFLAGS) -c main.c

nat_traversal.o:  nat_traversal.c 
	$(CC) $(CFLAGS) -c nat_traversal.c

nat_type.o:  nat_type.c
	$(CC) $(CFLAGS) -c nat_type.c

clean: 
	$(RM) nat_traversal *.o *~

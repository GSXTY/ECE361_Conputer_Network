CC=gcc
CFLAGS=-I. -g -O0 -lpthread

all: server client

server.o: server.c packet.h
	$(CC) -c server.c $(CFLAGS)

client.o: client.c packet.h
	$(CC) -c client.c $(CFLAGS)

packet.o: packet.c packet.h
	$(CC) -c packet.c $(CFLAGS)

server: server.o packet.o
	$(CC) -o server server.o packet.o  $(CFLAGS)

client: client.o packet.o
	$(CC) -o client client.o packet.o $(CFLAGS)

clean:
	rm -f *.o server client
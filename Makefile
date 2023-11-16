CC = gcc
LEX = flex
CFLAGS = -Wall

all: analyseur
	sudo ./analyseur

analyseur: analyseur.o 
	$(CC) -o analyseur analyseur.o -lpcap

analyseur.o: analyseur.c analyseur.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o

.PHONY: all clean
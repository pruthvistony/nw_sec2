
CC=gcc
CFLAGS=-Wall

LIBS=-lpcap

DEPS = ns_hw2.h
##DEPS = $(patsubst %,$(_DEPS))

OBJ = ns_hw2_pmadugundu.o 
##OBJ = $(patsubst %,$(_OBJ))

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

mydump: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.phony: clean

clean:
	rm -f mydump ns_hw2_pmadugundu.o

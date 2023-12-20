CC = gcc
CFLAGS = -Wall -g -lm
LD = gcc
LDFLAGS = -lm -Wall -g

all: mytar.o
	$(LD) $(LDFLAGS) -o mytar mytar.o
mytar: mytar.o
	$(LD) $(LDFLAGS) -o mytar mytar.o
mytar.o: mytar.c
	$(CC) $(CLFAGS) -c -o mytar.o mytar.c 
testCreate: mytar
	./mytar cvf archive2.tar ./testOneLongFileName
	~pn-cs357/demos/mytar cvf archive.tar ./testOneLongFileName
	diff archive2.tar archive.tar


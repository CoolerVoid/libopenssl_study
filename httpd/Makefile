CC=gcc
CFLAGS=-Wall -Wextra -Wno-unknown-pragmas -O2 
DFLAGS=-L/usr/lib -g -lssl -lcrypto
DIR=src/
DIROUT=bin/
UNAME_S := $(shell uname -s)

serverhttps: $(DIR)main.c 
	@echo "Compile... "
	$(CC) $(CFLAGS) $(DFLAGS) -c $(DIR)*.c 
	$(CC) -o $(DIROUT)serverhttps *.o $(LDFLAGS) $(DFLAGS)
	$(shell make clean)
	@echo "  "
	@echo " Next step, execute \"bin/serverhttps port_number\" to start...  "   
clean:
	rm -f *.o serverhttps

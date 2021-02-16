CC=gcc
CFLAGS=-Wall -pthread -std=c99
LDFLAGS=-lpthread -lrt -shared -fpic
PROJECT=secube-x64
BINOUT=$(PROJECT).so
PREFIX=./py
SRC_SECUBE_WRAPPER=$(wildcard ../src/Common/*.c) $(wildcard ../src/Host/*.c) $(wildcard secube-wrapper/*.c)
INC=-I../src/Common -I../src/Host -Isecube-wrapper
DEF=-D_GNU_SOURCE

all: dirs bin/$(BINOUT)

bin/$(BINOUT):
	$(CC) $(DEF) $(INC) $^ $(CFLAGS) $(SRC_SECUBE_WRAPPER) $(LDFLAGS) -o $@

dirs:
	mkdir -p bin
	mkdir -p obj

clean:
	rm -f bin/$(BINOUT)

install:
	mkdir -p $(PREFIX)
	install -m 0755 bin/$(BINOUT) $(PREFIX)/$(BINOUT)
	
.PHONY: dirs all clean install


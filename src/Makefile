# Auto generated file, modify needed to let `make` run correctly.

TARGET := ../bin
CC := gcc
MACRO := -D "PROGNAME=\"ToyCDN\"" -D "VERSION=\"1.0.0013-Alpha\""
PACKAGE_PREFIX := 
CFLAGS := $(MACRO) -O2 -Wall -Werror -Wextra -I ./include
PROG := nameserver dnstest
OUT := log.o mydns.o
LIB := -lpthread

.PHONY: all
all: $(PROG)

dnstest: $(OUT)
	$(CC) $(CFLAGS) -o $(TARGET)/$(PACKAGE_PREFIX)dnstest dnstest.c $(OUT) $(LIB)

nameserver: $(OUT)
	$(CC) $(CFLAGS) -o $(TARGET)/$(PACKAGE_PREFIX)nameserver nameserver.c $(OUT) $(LIB)

mydns.o:
	$(CC) $(CFLAGS) -c mydns.c

log.o:
	$(CC) $(CFLAGS) -c log.c

.PHONY: clean
clean:
	-rm -f *.o $(PROG) *.exe *~
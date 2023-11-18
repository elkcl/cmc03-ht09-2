.PHONY: all clean

CC = gcc
CFLAGS = -O2
LD = gcc
LDFLAGS = -lm

smarthome.o: smarthome.c
	$(CC) -c --std=gnu2x $(CFLAGS) -o $@ $<

smarthome: smarthome.o
	$(LD) -lcurl $(LDFLAGS) -o $@ $^

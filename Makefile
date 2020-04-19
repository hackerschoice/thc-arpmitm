CC=gcc
CFLAGS=-Wall -O2 -static
LIBS=-lm
###LIBNET_DEFS=`libnet-config --defines`
LIBNET_LIBS=`libnet-config --libs`

all:

	$(CC) $(CFLAGS) $(LIBNET_DEFS) thc-arpmitm.c -o thc-arpmitm $(LIBS) $(LIBNET_LIBS)
	strip thc-arpmitm

clean:
	rm -vf thc-arpmitm

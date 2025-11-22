cc=gcc
cflags=-Wall -Wextra -pedantic $(incdirs) -g $(opt)
opt=-O2
incdirs=-Iinclude
bindir=bin

cfiles=src/server.c
cfiles2=src/client.c

binary=$(bindir)/server
binary2=$(bindir)/client

all: $(binary)

$(binary): $(bindir)
	$(cc) $(cflags) $(cfiles) -o $@
	$(cc) $(cflags) $(cfiles2) -o $(binary2)

run:
	$(binary)

$(bindir):
	mkdir -p $@

clean:
	rm -f $(binary)
	rm -f $(binary2)

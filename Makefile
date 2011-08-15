CFLAGS=-Wall -O1

PREFIX=/usr/local
BINDIR=${PREFIX}/bin
LIBDIR=${PREFIX}/lib

all: private-mount glick2 to_c glick_fs

clean:
	rm -f private-mount glick2 to_c glick_fs

install: private-mount
	install -m 4755 -o root private-mount ${BINDIR}

private-mount: private-mount.c
	gcc -o private-mount private-mount.c ${CFLAGS}

to_c: to_c.c
	gcc -o to_c to_c.c ${CFLAGS}

sh.h:	/bin/sh to_c
	./to_c /bin/sh  binsh > sh.h

glick2: glick2.c sh.h
	gcc ${CFLAGS} `pkg-config fuse --cflags --libs` glick2.c -o glick2 -DBINDIR=\"${BINDIR}\"

glick_fs: glick_fs.c glick.h
	gcc ${CFLAGS} `pkg-config fuse glib-2.0 --cflags --libs` glick_fs.c -o glick_fs

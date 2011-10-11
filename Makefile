CFLAGS=-Wall -O1 -g -D_FILE_OFFSET_BITS=64

PREFIX=/usr/local
BINDIR=${PREFIX}/bin
LIBEXECDIR=${PREFIX}/libexec
LIBDIR=${PREFIX}/lib

all: glick-helper glick-runner glick_fs create_bundle makershared

clean:
	rm -f glick-helper glick2 glick_fs create_bundle

install: glick-helper
	install -m 4755 -o root glick-helper ${LIBEXECDIR}

glick-helper: glick-helper.c
	gcc -o glick-helper glick-helper.c ${CFLAGS}

makershared: makershared.c
	gcc -o makershared makershared.c ${CFLAGS}

glick-runner: runner.c
	gcc ${CFLAGS} `pkg-config fuse glib-2.0 --cflags --libs` runner.c -o glick-runner -DLIBEXECDIR=\"${LIBEXECDIR}\"

glick_fs: glick_fs.c glick.h
	gcc ${CFLAGS} `pkg-config fuse glib-2.0 gthread-2.0 gio-2.0 --cflags --libs` glick_fs.c -o glick_fs

create_bundle: create_bundle.c
	gcc ${CFLAGS} `pkg-config glib-2.0 gio-2.0 --cflags --libs` create_bundle.c -o create_bundle

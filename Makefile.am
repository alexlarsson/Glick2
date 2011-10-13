NULL =

AM_CPPFLAGS =					\
	-I$(top_srcdir)				\
	-I$(top_builddir)			\
	$(GLIB_CFLAGS)				\
	$(GIO_CFLAGS)				\
	$(FUSE_CFLAGS)				\
	$(X11_CFLAGS)				\
	-DLIBEXECDIR=\"$(libexecdir)\"		\
	-DBINDIR=\"$(bindir)\"			\
	-DLIBDIR=\"$(libdir)\"			\
	$(NULL)

bin_PROGRAMS =					\
	glick-launcher				\
	glick-session-launcher			\
	glick-mkbundle				\
	glick-runner				\
	glick-fs				\
	glick-makershared			\
	$(NULL)

libexec_PROGRAMS =				\
	glick-helper				\
	$(NULL)


glick_helper_SOURCES = helper.c
glick_helper_LDADD = $(GLIB_LIBS)

glick_launcher_SOURCES = launcher.c
glick_launcher_LDADD = $(GLIB_LIBS) $(X11_LIBS)

glick_session_launcher_SOURCES = session.c

glick_makershared_SOURCES = makershared.c

glick_runner_SOURCES = runner.c
glick_runner_LDADD = $(GLIB_LIBS) $(FUSE_LIBS)

glick_fs_SOURCES = fs.c
glick_fs_LDADD = $(GIO_LIBS) $(FUSE_LIBS)

glick_mkbundle_SOURCES = mkbundle.c
glick_mkbundle_LDADD = $(GIO_LIBS)

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(BUNDLE_PREFIX)
	$(mkinstalldirs) $(DESTDIR)$(SESSION_PREFIX)

install-exec-hook:
	chown root $(DESTDIR)$(libexecdir)/glick-helper
	chmod 4755 $(DESTDIR)$(libexecdir)/glick-helper
	chown root $(DESTDIR)$(bindir)/glick-session-launcher
	chmod 4755 $(DESTDIR)$(bindir)/glick-session-launcher

ChangeLog:
	$(AM_V_GEN) if test -d "$(srcdir)/.git"; then \
	  (GIT_DIR=$(top_srcdir)/.git ./missing --run git log --stat) | fmt --split-only > $@.tmp \
	  && mv -f $@.tmp $@ \
	  || ($(RM) $@.tmp; \
	      echo Failed to generate ChangeLog, your ChangeLog may be outdated >&2; \
	      (test -f $@ || echo git-log is required to generate this file >> $@)); \
	else \
	  test -f $@ || \
	  (echo A git checkout and git-log is required to generate ChangeLog >&2 && \
	  echo A git checkout and git-log is required to generate this file >> $@); \
	fi

mimedir = $(datadir)/mime/packages
mime_DATA = glick2.xml

UPDATE_MIME = \
	if [ -f $(DESTDIR)$(datadir)/mime/packages/freedesktop.org.xml ] ; then \
		if which update-mime-database>/dev/null 2>&1; then \
			update-mime-database $(DESTDIR)$(datadir)/mime; \
		fi \
	fi

install-data-hook:
if UPDATE_CACHES
	$(UPDATE_MIME)
else
	@true
endif

uninstall-hook:
if UPDATE_CACHES
	$(UPDATE_MIME)
else
	@true
endif

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
	-e 's|@prefix[@]|$(prefix)|g'

binfmtdir = ${sysconfdir}/binfmt.d
binfmt_DATA = glick2.conf

# Binfmt config file
glick2.conf: Makefile glick2.conf.in
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	mv $@.tmp $@

# Autostart file
desktopdir = $(sysconfdir)/xdg/autostart
desktop_DATA = glick.desktop

glick.desktop: Makefile glick.desktop.in
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	mv $@.tmp $@

EXTRA_DIST=glick2.conf.in glick.desktop.in

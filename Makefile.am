NULL =

AM_CPPFLAGS =					\
	-I$(top_srcdir)				\
	-I$(top_builddir)			\
	$(GLIB_CFLAGS)				\
	$(GIO_CFLAGS)				\
	$(FUSE_CFLAGS)				\
	-DLIBEXECDIR=\"$(libexecdir)/\"

bin_PROGRAMS =					\
	glick-mkbundle				\
	glick-runner				\
	glick-fs				\
	makershared				\
	$(NULL)

libexec_PROGRAMS =				\
	glick-helper				\
	$(NULL)


glick_helper_SOURCES = helper.c
glick_helper_LDADD = $(GLIB_LIBS)

makershared_SOURCES = makershared.c

glick_runner_SOURCES = runner.c
glick_runner_LDADD = $(GLIB_LIBS) $(FUSE_LIBS)

glick_fs_SOURCES = fs.c
glick_fs_LDADD = $(GIO_LIBS) $(FUSE_LIBS)

glick_mkbundle_SOURCES = mkbundle.c
glick_mkbundle_LDADD = $(GIO_LIBS)

install-exec-hook:
	chown root $(DESTDIR)$(libexecdir)/glick-helper
	chmod 4755 $(DESTDIR)$(libexecdir)/glick-helper

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

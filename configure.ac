AC_PREREQ([2.67])
AC_INIT([glick],[2.0])
AC_CONFIG_SRCDIR([mkbundle.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
# Enable silent rules is available
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE([enable])
AC_CONFIG_FILES([Makefile])

AC_SYS_LARGEFILE
AC_PROG_CC
AC_PROG_INSTALL

glib_modules="glib-2.0"
PKG_CHECK_MODULES(GLIB, [$glib_modules])

gio_modules="glib-2.0 gthread-2.0 gio-2.0"
PKG_CHECK_MODULES(GIO, [$gio_modules])

fuse_modules="fuse"
PKG_CHECK_MODULES(FUSE, [$fuse_modules])

if test "x$GCC" = "xyes"; then
  case " $CFLAGS " in
  *[[\ \	]]-Wall[[\ \	]]*) ;;
  *) CFLAGS="$CFLAGS -Wall" ;;
  esac
fi

AC_HEADER_STDC

AC_OUTPUT

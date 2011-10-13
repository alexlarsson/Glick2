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

x11_modules="x11"
PKG_CHECK_MODULES(X11, [$x11_modules])

AC_ARG_WITH(bundle_prefix,
	AS_HELP_STRING([--with-bundle-prefix=DIR],[Prefix used for bundles @<:@/opt/bundle@:>@]),
	[ac_with_bundle_prefix=$withval],
	[ac_with_bundle_prefix="/opt/bundle"])
AC_DEFINE_UNQUOTED(BUNDLE_PREFIX, "$ac_with_bundle_prefix", [The default prefix for bundles])
BUNDLE_PREFIX=$ac_with_bundle_prefix
AC_SUBST(BUNDLE_PREFIX)

AC_ARG_WITH(session_prefix,
	AS_HELP_STRING([--with-session_prefix=DIR],[Prefix used for bundle exports @<:@/opt/session@:>@]),
	[ac_with_session_prefix=$withval],
	[ac_with_session_prefix="/opt/session"])
AC_DEFINE_UNQUOTED(SESSION_PREFIX, "$ac_with_session_prefix", [The default prefix for bundle exports])
SESSION_PREFIX=$ac_with_session_prefix
AC_SUBST(SESSION_PREFIX)

if test "x$GCC" = "xyes"; then
  case " $CFLAGS " in
  *[[\ \	]]-Wall[[\ \	]]*) ;;
  *) CFLAGS="$CFLAGS -Wall" ;;
  esac
fi

AC_ARG_ENABLE(caches,
		AS_HELP_STRING([--enable-caches],[Run update-* to update mime caches when installing [[default=yes]]]),
		[enable_caches=$enableval],
		[enable_caches="yes"])

AM_CONDITIONAL(UPDATE_CACHES, test x"$enable_caches" = "xyes")

AC_ARG_ENABLE(setuid-install,
		AS_HELP_STRING([--disable-setuid-install],[Don't set setuid flags on binaries during install]),
		[enable_setuid_install=$enableval],
		[enable_setuid_install="yes"])

AM_CONDITIONAL(SETUID_INSTALL, test x"$enable_setuid_install" = "xyes")

AC_OUTPUT

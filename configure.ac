# $Id$

AC_INIT(file, 6.5)
RELEASE=6.5
AC_SUBST(RELEASE)

AC_CONFIG_AUX_DIR(etc)
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CANONICAL_HOST
case $host_os in
	*netbsd*)
		AC_DEFINE(_OPENBSD_SOURCE)
		;;
	*linux*)
		AC_DEFINE(_GNU_SOURCE)
		;;
	*)
		;;
esac

: ${CFLAGS=""}

CPPFLAGS="$CPPFLAGS -I/usr/local/include"
LDFLAGS="$LDFLAGS -L/usr/local/lib"

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

AC_SYS_LARGEFILE

test "$sysconfdir" = '${prefix}/etc' && sysconfdir=/etc

AC_ARG_ENABLE(
	debug,
	AS_HELP_STRING([--enable-debug], [create a debug build]),
	found_debug=$enable_debug
)
AM_CONDITIONAL(IS_DEBUG, test "x$found_debug" = xyes)

#
# This option only exists because of shit operating systems.
AC_ARG_ENABLE(
	pie,
	AS_HELP_STRING([--disable-pie], [disable PIE build]),
	found_pie=$enable_pie,
	found_pie=yes
)
AM_CONDITIONAL(IS_PIE, test "x$found_pie" = xyes)

#
# This option only exists because some Linux kernels have prctl
# but do not actually implement seccomp-bpf.
AC_ARG_ENABLE(
	prctl,
	AS_HELP_STRING([--disable-prctl], [disable seccomp-bpf (Linux)]),
	found_prctl=$enable_prctl,
	found_prctl=yes
)

#
# Configure unprivileged user.
AC_ARG_WITH(
	[user],
	AS_HELP_STRING([--with-user=user],[privsep user (default: "_file")]),
	[AC_DEFINE_UNQUOTED([FILE_USER], "$withval", [username to run with])]
)

AC_CHECK_HEADERS([sys/endian.h endian.h])
AC_CHECK_HEADERS([sys/tree.h], [], [needs_compat=yes;break])
case $host_os in
	*netbsd*)
		# NetBSD vis SIGSEGV's
		needs_compat=yes
		;;
	*)
		AC_CHECK_HEADERS([vis.h], [], [needs_compat=yes;break])
		;;
esac
AC_CHECK_HEADERS([sys/queue.h imsg.h], [], [needs_compat=yes;break],
	[#include <sys/types.h>
	#include <sys/queue.h>])
AS_IF([test "x$needs_compat" = "xyes"], [CPPFLAGS="$CPPFLAGS -Icompat"])

AC_CHECK_FUNCS(
	[ \
		issetugid \
		setgroups \
	]
)

AC_SEARCH_LIBS(
	imsg_init,
	[util],
	found_imsg=yes,
	found_imsg=no
)
if test "x$found_imsg" = xyes; then
	AC_DEFINE(HAVE_IMSG)
fi
AM_CONDITIONAL(NO_IMSG, [test "x$found_imsg" = xno])

AC_CHECK_DECL(strlcpy, found_strlcpy=yes, found_strlcpy=no)
if test "x$found_strlcpy" = xyes; then
	AC_DEFINE(HAVE_STRLCPY)
fi
AM_CONDITIONAL(NO_STRLCPY, [test "x$found_strlcpy" = xno])

AC_CHECK_DECL(strlcat, found_strlcat=yes, found_strlcat=no)
if test "x$found_strlcat" = xyes; then
	AC_DEFINE(HAVE_STRLCAT)
fi
AM_CONDITIONAL(NO_STRLCAT, [test "x$found_strlcat" = xno])

AC_CHECK_FUNC(explicit_bzero, found_explicit_bzero=yes, found_explicit_bzero=no)
if test "x$found_explicit_bzero" = xyes; then
	AC_DEFINE(HAVE_EXPLICIT_BZERO)
fi
AM_CONDITIONAL(NO_EXPLICIT_BZERO, [test "x$found_explicit_bzero" = xno])

AC_CHECK_FUNC(freezero, found_freezero=yes, found_freezero=no)
if test "x$found_freezero" = xyes; then
	AC_DEFINE(HAVE_FREEZERO)
fi
AM_CONDITIONAL(NO_FREEZERO, [test "x$found_freezero" = xno])

AC_CHECK_FUNC(setresgid, found_setresgid=yes, found_setresgid=no)
if test "x$found_setresgid" = xyes; then
	AC_DEFINE(HAVE_SETRESGID)
fi
AM_CONDITIONAL(NO_SETRESGID, [test "x$found_setresgid" = xno])

AC_CHECK_FUNC(setresuid, found_setresuid=yes, found_setresuid=no)
if test "x$found_setresuid" = xyes; then
	AC_DEFINE(HAVE_SETRESUID)
fi
AM_CONDITIONAL(NO_SETRESUID, [test "x$found_setresuid" = xno])

# Used by setresgid compat
AC_CHECK_FUNC(setregid, found_setregid=yes, found_setregid=no)
if test "x$found_setregid" = xyes; then
	AC_DEFINE(HAVE_SETREGID)
fi
AM_CONDITIONAL(NO_SETREGID, [test "x$found_setregid" = xno])

# Used by setresuid compat
AC_CHECK_FUNC(setreuid, found_setreuid=yes, found_setreuid=no)
if test "x$found_setreuid" = xyes; then
	AC_DEFINE(HAVE_SETREUID)
fi
AM_CONDITIONAL(NO_SETREUID, [test "x$found_setreuid" = xno])

AC_CHECK_FUNC(reallocarray, found_reallocarray=yes, found_reallocarray=no)
if test "x$found_reallocarray" = xyes; then
	AC_DEFINE(HAVE_REALLOCARRAY)
fi
AM_CONDITIONAL(NO_REALLOCARRAY, [test "x$found_reallocarray" = xno])

AC_CHECK_FUNC(recallocarray, found_recallocarray=yes, found_recallocarray=no)
if test "x$found_recallocarray" = xyes; then
	AC_DEFINE(HAVE_RECALLOCARRAY)
fi
AM_CONDITIONAL(NO_RECALLOCARRAY, [test "x$found_recallocarray" = xno])

AC_CHECK_FUNC(strnvis, found_strnvis=yes, found_strnvis=no)
dnl NetBSD added an strnvis and unfortunately made it incompatible with the
dnl existing one in OpenBSD and Linux's libbsd (the former having existed
dnl for over ten years). Despite this incompatibility being reported during
dnl development (see http://gnats.netbsd.org/44977) they still shipped it.
dnl Even more unfortunately FreeBSD and later MacOS picked up this incompatible
dnl implementation.  Try to detect this mess, and assume the only safe option
dnl if we're cross compiling.
dnl
dnl OpenBSD, 2001: strnvis(char *dst, const char *src, size_t dlen, int flag);
dnl NetBSD: 2012,  strnvis(char *dst, size_t dlen, const char *src, int flag);
if test "x$found_strnvis" = "xyes"; then
 AC_MSG_CHECKING([for working strnvis])
 AC_RUN_IFELSE(
  [AC_LANG_PROGRAM([[
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <vis.h>
static void sighandler(int sig) { _exit(1); }
  ]], [[
 char dst[16];

 signal(SIGSEGV, sighandler);
 if (strnvis(dst, "src", 4, 0) && strcmp(dst, "src") == 0)
  exit(0);
 exit(1)
  ]])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
   found_strnvis="no" ],
 [AC_MSG_WARN([cross compiling: assuming broken])
   found_strnvis="no" ]
 )
 if test "x$found_strnvis" = xyes; then
	AC_DEFINE(HAVE_VIS)
 fi
fi
AM_CONDITIONAL(NO_VIS, [test "x$found_strnvis" = xno])

if test "x$found_prctl" = xyes; then
	AC_CHECK_FUNC(prctl, found_prctl=yes, found_prctl=no)
	if test "x$found_prctl" = xyes; then
		AC_DEFINE(HAVE_PRCTL)
	fi
fi
AM_CONDITIONAL(PRCTL, [test "x$found_prctl" = xyes])

# Needs to be last as the preprocessor hack breaks something
AC_CHECK_FUNC(pledge, found_pledge=yes, found_pledge=no)
if test "x$found_pledge" = xno; then
	CPPFLAGS="$CPPFLAGS -D\"pledge(promises,paths)=0\""
fi

AC_OUTPUT(Makefile)

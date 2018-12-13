# $Id$

AC_INIT(file, 6.2)
RELEASE=6.2
AC_SUBST(RELEASE)

AC_CONFIG_AUX_DIR(etc)
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CANONICAL_HOST

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
AC_CHECK_HEADERS([vis.h], [], [needs_compat=yes;break])
AC_CHECK_HEADERS([sys/queue.h imsg.h], [], [needs_compat=yes;break],
	[#include <sys/types.h>
	#include <sys/queue.h>])
AS_IF([test "x$needs_compat" = "xyes"], [CPPFLAGS="$CPPFLAGS -Icompat"])

AC_CHECK_FUNCS(
	[ \
		issetugid \
		setgroups \
		setresuid \
		setresgid \
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

AC_CHECK_FUNC(vis, found_vis=yes, found_vis=no)
if test "x$found_vis" = xyes; then
	AC_DEFINE(HAVE_VIS)
fi
AM_CONDITIONAL(NO_VIS, [test "x$found_vis" = xno])

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

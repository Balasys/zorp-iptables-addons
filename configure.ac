AC_INIT([iptables-addons], [6.0.1])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_INSTALL
AM_INIT_AUTOMAKE([-Wall])
AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AM_PROG_LIBTOOL

if test "x$prefix" = "xNONE"; then
        prefix=$ac_default_prefix
fi

AC_CHECK_HEADERS([linux/netfilter/x_tables.h], [],
	[AC_MSG_ERROR([You need to have linux/netfilter/x_tables.h])])
PKG_CHECK_MODULES([xtables], [xtables >= 1.4.5])

regular_CFLAGS="-Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe";
regular_CPPFLAGS="${largefile_cppflags} -D_REENTRANT \
	-DXTABLES_LIBDIR=\\\"\${xtlibdir}\\\" -DXTABLES_INTERNAL";
kinclude_CPPFLAGS="";
if [[ -n "$kbuilddir" ]]; then
	kinclude_CPPFLAGS="$kinclude_CPPFLAGS -I$kbuilddir/include/uapi -I$kbuilddir/include";
fi;
if [[ -n "$ksourcedir" ]]; then
	kinclude_CPPFLAGS="$kinclude_CPPFLAGS -I$ksourcedir/include/uapi -I$ksourcedir/include";
fi;

ADDONS_DIR="${libdir}/xtables"

AC_SUBST(ADDONS_DIR)

AC_SUBST([regular_CFLAGS])
AC_SUBST([regular_CPPFLAGS])
AC_SUBST([xtables_CFLAGS])
AC_SUBST([kinclude_CPPFLAGS])

AC_CONFIG_FILES([Makefile extensions/GNUmakefile	])
AC_OUTPUT

AM_CFLAGS = \
	${regular_CFLAGS} \
	${xtables_CFLAGS}

AM_CPPFLAGS = \
	${regular_CPPFLAGS} \
	${kinclude_CPPFLAGS} \
	-I${top_srcdir}/include

AM_LDFLAGS = \
	-avoid-version

libdir = ${ADDONS_DIR}

lib_LTLIBRARIES = \
	libxt_KZORP.la \
	libxt_rule.la \
	libxt_service.la \
	libxt_socket_kzorp.la \
	libxt_zone.la

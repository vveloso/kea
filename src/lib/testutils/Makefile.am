AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES)
AM_CXXFLAGS=$(KEA_CXXFLAGS)

noinst_SCRIPTS = dhcp_test_lib.sh

if HAVE_GTEST
noinst_LTLIBRARIES = libkea-testutils.la

libkea_testutils_la_SOURCES  = io_utils.cc io_utils.h
libkea_testutils_la_SOURCES += unix_control_client.h unix_control_client.cc
libkea_testutils_la_CPPFLAGS = $(AM_CPPFLAGS) $(GTEST_INCLUDES)
libkea_testutils_la_LIBADD  = $(top_builddir)/src/lib/asiolink/libkea-asiolink.la
libkea_testutils_la_LIBADD += $(top_builddir)/src/lib/dns/libkea-dns++.la
endif

# Include common libraries being used by shell-based tests.
SHLIBS = dhcp_test_lib.sh.in

EXTRA_DIST = $(SHLIBS)

CLEANFILES = dhcp_test_lib.sh

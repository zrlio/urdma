# Makefile.am

# Userspace Software iWARP library for DPDK
#
# Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
#
# Copyright (c) 2016, University of New Hampshire InterOperability Laboratory
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# BSD license below:
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#   - Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#
#   - Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
#   - Neither the name of IBM nor the names of its contributors may be
#     used to endorse or promote products derived from this software without
#     specific prior written permission.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

ACLOCAL_AMFLAGS = -I config

AM_CFLAGS = $(EXTRA_CFLAGS) \
	    -fno-strict-aliasing \
	    -fvisibility=hidden

EXTRA_DIST = gpl-2.0.txt config/version.sh
include_HEADERS = include/urdma_kabi.h \
		include/urdmad_private.h \
		include/proto.h \
		include/proto_memcached.h \
		include/proto_trp.h \
		include/kvstore_limits.h \
		include/kvstore_storage.h

lib_LTLIBRARIES = src/liburdma/liburdma.la
src_liburdma_liburdma_la_SOURCES = \
	src/liburdma/driver.c \
	src/liburdma/interface.c \
	src/liburdma/interface.h \
	src/liburdma/verbs.c \
	src/liburdma/verbs.h \
	src/util/config_file.c \
	src/util/config_file.h \
	src/util/list.h \
	src/util/util.c \
	src/util/util.h
src_liburdma_liburdma_la_CFLAGS = $(MACHINE_CFLAGS)
src_liburdma_liburdma_la_CPPFLAGS = -Durdma_confdir='"$(sysconfdir)/rdma"' -I$(srcdir)/include -I$(srcdir)/src/util $(LIBNL3_CFLAGS) $(JSON_C_CFLAGS) $(DPDK_CPPFLAGS)
src_liburdma_liburdma_la_LDFLAGS = -avoid-version \
	-release @IBV_DEVICE_LIBRARY_EXTENSION@ $(DPDK_LDFLAGS)
src_liburdma_liburdma_la_LIBADD = $(LIBNL3_LIBS) $(JSON_C_LIBS) $(DPDK_LIBS)
verbsconfdir = $(sysconfdir)/libibverbs.d
dist_verbsconf_DATA = src/liburdma/urdma.driver

bin_PROGRAMS = src/urdmad/urdmad
src_urdmad_urdmad_SOURCES = \
	src/urdmad/main.c \
	src/urdmad/interface.h \
	src/urdmad/kni.c \
	src/urdmad/kni.h \
	src/util/config_file.c \
	src/util/config_file.h \
	src/util/list.h
src_urdmad_urdmad_CFLAGS = $(MACHINE_CFLAGS)
src_urdmad_urdmad_CPPFLAGS = -Durdma_confdir='"$(sysconfdir)/rdma"' -I$(srcdir)/include -I$(srcdir)/src/util $(LIBNL3_CFLAGS) $(JSON_C_CFLAGS) $(DPDK_CPPFLAGS)
src_urdmad_urdmad_LDFLAGS = $(DPDK_LDFLAGS)
src_urdmad_urdmad_LDADD = $(LIBNL3_LIBS) $(JSON_C_LIBS) $(DPDK_LIBS)

bin_PROGRAMS += src/udp_pingpong/udp_pingpong
src_udp_pingpong_udp_pingpong_SOURCES = \
	src/udp_pingpong/main.c \
	src/util/util.c \
	src/util/util.h
src_udp_pingpong_udp_pingpong_CFLAGS = $(MACHINE_CFLAGS)
src_udp_pingpong_udp_pingpong_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/src/util $(DPDK_CPPFLAGS)
src_udp_pingpong_udp_pingpong_LDFLAGS = $(DPDK_LDFLAGS)
src_udp_pingpong_udp_pingpong_LDADD = $(DPDK_LIBS)

bin_PROGRAMS += src/mkkvstore/mkkvstore
src_mkkvstore_mkkvstore_SOURCES = \
	src/mkkvstore/main.c \
	src/util/util.c \
	src/util/util.h
src_mkkvstore_mkkvstore_CFLAGS = $(MACHINE_CFLAGS)
src_mkkvstore_mkkvstore_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/src/util $(DPDK_CPPFLAGS)
src_mkkvstore_mkkvstore_LDFLAGS = $(DPDK_LDFLAGS)
src_mkkvstore_mkkvstore_LDADD = $(DPDK_LIBS) -lm

bin_PROGRAMS += src/verbs_pingpong/verbs_pingpong
src_verbs_pingpong_verbs_pingpong_SOURCES = \
	src/verbs_pingpong/main.c
src_verbs_pingpong_verbs_pingpong_CFLAGS = $(MACHINE_CFLAGS)
src_verbs_pingpong_verbs_pingpong_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/src/liburdma $(DPDK_CPPFLAGS)
src_verbs_pingpong_verbs_pingpong_LDFLAGS = $(DPDK_LDFLAGS)
src_verbs_pingpong_verbs_pingpong_LDADD = $(DPDK_LIBS)

bin_PROGRAMS += src/kvstore_server/kvstore_server
src_kvstore_server_kvstore_server_SOURCES = \
	src/kvstore_server/kvstore.c \
	src/kvstore_server/kvstore.h \
	src/kvstore_server/main.c \
	src/kvstore_server/nvm.c \
	src/kvstore_server/nvm.h \
	src/kvstore_server/options.c \
	src/kvstore_server/options.h \
	src/util/util.c \
	src/util/util.h
src_kvstore_server_kvstore_server_CFLAGS = $(MACHINE_CFLAGS)
src_kvstore_server_kvstore_server_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/src/util -I$(srcdir)/src/liburdma $(DPDK_CPPFLAGS)
src_kvstore_server_kvstore_server_LDFLAGS = $(DPDK_LDFLAGS)
src_kvstore_server_kvstore_server_LDADD = src/liburdma/liburdma.la $(DPDK_LIBS) -lm

bin_PROGRAMS += src/kvstore_client/kvstore_client
src_kvstore_client_kvstore_client_SOURCES = \
	src/kvstore_client/main.c \
	src/kvstore_client/options.c \
	src/kvstore_client/options.h \
	src/util/util.c \
	src/util/util.h
src_kvstore_client_kvstore_client_CFLAGS = $(MACHINE_CFLAGS)
src_kvstore_client_kvstore_client_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/src/util -I$(srcdir)/src/liburdma $(DPDK_CPPFLAGS)
src_kvstore_client_kvstore_client_LDFLAGS = $(DPDK_LDFLAGS)
src_kvstore_client_kvstore_client_LDADD = src/liburdma/liburdma.la $(DPDK_LIBS) -lm

# Disable the uninstall check since the kernel build system doesn't
# provide a module uninstall target.
distuninstallcheck:
	@:

dist-hook:
	$(srcdir)/config/version.sh $(srcdir) >$(top_distdir)/.version

SUBDIRS = src/kmod

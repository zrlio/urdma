# Makefile

# Userspace Software iWARP library for DPDK
#
# Authors: Patrick MacArthur <pam@zurich.ibm.com>
#
# Copyright (c) 2016, IBM Corporation
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

ifeq ($(strip $(RTE_SDK)),)
$(error "Please set RTE_SDK to the DPDK install location.")
endif

RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk
BASE_OUTPUT = $(RTE_OUTPUT)
BASE_SRCDIR = $(RTE_SRCDIR)
export BASE_SRCDIR

# Flags to be added for debug purposes.  By default, add debug symbols to
# objects but do not enable assertions.
DEBUG_FLAGS ?= -g -DNDEBUG
export DEBUG_FLAGS

# Define $(distdir) now that we know what our source directory is and therefore
# what version revision control gives us
package = dpdk-write
version = $(shell config/version.sh $(RTE_SRCDIR))
tarname = dpdk-write
distdir = $(tarname)-$(version)

sysconfdir ?= /etc
export sysconfdir

KMOD_DIRS-y := src/kmod

DIRS-y := src/libusiw \
	src/kvstore_server src/kvstore_client \
	src/udp_pingpong src/verbs_pingpong src/mkkvstore \
	$(KMOD_DIRS-y) $(PRIVATE_DIRS)

NODIST_DIRS := doc/report
DIST_DIRS := $(filter-out $(NODIST_DIRS),$(DIRS-y))

export DIST_DIRS

EXTRA_DIST := Makefile NEWS config/dist.mk config/distfiles.mk \
	config/module.mk config/subdir.mk \
	src/util/util.c src/util/util.h \
	include/kvstore_limits.h include/kvstore_storage.h \
	include/proto.h include/proto_memcached.h include/siw_user.h \
	doc/protocol.txt doc/implementation.txt
EXTRA_DIRS := config doc include src/util

include $(BASE_SRCDIR)/config/subdir.mk

CTAGS_DIRS := $(DIRS-y) include
.PHONY: ctags
ctags:
	$(if $(V),,@echo "  GEN ctags")
	$(Q)ctags -f $(RTE_SRCDIR)/tags -R \
		$(foreach d,$(CTAGS_DIRS),$(patsubst %,$(RTE_SRCDIR)/%,$(d)))

.distfiles:
	$(Q)$(RM) $(BASE_OUTPUT)/.distfiles
	$(Q)for d in $(DIST_DIRS); do \
		make -f $(RTE_SRCDIR)/$$d/Makefile \
			CUR_SUBDIR=$$d \
			distfiles \
			>>$(BASE_OUTPUT)/.distfiles; \
	done


.PHONY: dist
dist distcheck: .distfiles
	$(Q)$(MAKE) -f $(RTE_SRCDIR)/config/dist.mk \
		EXTRA_DIST="$(EXTRA_DIST)" EXTRA_DIRS="$(EXTRA_DIRS)" \
		distdir=$(distdir) version=$(version) $@

.PHONY: clean-local
clean: clean-local
clean-local:
	$(Q)$(RM) $(BASE_OUTPUT)/.distfiles

.PHONY: modules_install
modules_install: $(KMOD_DIRS-y)

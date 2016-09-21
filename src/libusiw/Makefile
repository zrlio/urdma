#
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

ifeq ($(BASE_SRCDIR),)
$(error "Please run make on the top-level directory")
endif

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
SHARED = libusiw-rdmav2.so

VPATH += $(BASE_SRCDIR)/src/util

# all source are stored in SRCS-y
SRCS-y := config_file.c driver.c interface.c kni.c verbs.c util.c
NODIST_SRCS := util.c
HEADERS := config_file.h interface.h kni.h list.h verbs.h

CFLAGS_driver.o := -Dusiw_confdir=\"$(sysconfdir)/rdma\"

CFLAGS += -std=gnu11 -O2 -fvisibility=hidden
CFLAGS += $(DEBUG_FLAGS) $(WERROR_FLAGS) -Wno-cast-qual -Wno-error=unused-parameter
CFLAGS += -I$(BASE_SRCDIR)/include -I$(BASE_SRCDIR)/src/util -I$(RTE_SRCDIR)
CFLAGS += $(shell pkg-config --cflags libnl-route-3.0 libnl-3.0 json-c)
LDLIBS += -lrdmacm -libverbs -ldpdk
LDLIBS += $(shell pkg-config --libs libnl-route-3.0 libnl-3.0 json-c)

POSTCLEAN += target-libclean
include $(RTE_SDK)/mk/rte.extshared.mk
include $(BASE_SRCDIR)/config/distfiles.mk

target-libclean:
	$(RM) $(RTE_OUTPUT)/lib/$(SHARED) $(RTE_OUTPUT)/.$(SHARED).cmd \
		$(RTE_OUTPUT)/_clean

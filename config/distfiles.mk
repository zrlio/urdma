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

# To be included in subdir Makefiles; this adds a target to print out the files
# in this directory that should be distributed in a tarball, in Makefile
# format.

# Input variables:
#    $(SRCS-y): Sources that were requested to be included in the build
#    $(HEADERS): C header files that are required by the source files above
#    $(EXTRA_DIST): Any other files that should be included in the distribution
#
# The Makefile is always included in the distribution.

DEFAULT_DIST := Makefile

DIST_SRCS := $(filter-out $(NODIST_SRCS),$(SRCS-y))

distfiles:
	@echo DISTFILES-$(CUR_SUBDIR) += $(DEFAULT_DIST) $(DIST_SRCS) $(HEADERS) $(EXTRA_DIST)

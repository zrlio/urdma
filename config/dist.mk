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

# To be called by the *root* makefile.  This requires that .distfiles has
# already been generated.  This file contains the list of files that should be
# distributed for every directory in the project.

# Input variables:
#   $(RTE_OUTPUT): Top-level build output directory.  The .distfiles file will
#   be placed in this directory.
#   $(distdir): The base name of the tarball.
#   $(DIST_DIRS): The set of directories that are built as part of the project.
#   $(EXTRA_DIRS): Directories which do not contain a Makefile but should be
#   included in the distribution.
#   $(EXTRA_DIST): Files that are not built by any Makefile but should be
#   included in the distribution.

include $(RTE_OUTPUT)/.distfiles

define add_to_distfiles
DISTFILES += $(patsubst %,$(1)/%,$(DISTFILES-$(1)))
endef

DISTFILES = $(EXTRA_DIST)
$(foreach d,$(DIST_DIRS),$(eval $(call add_to_distfiles,$(d))))

.PHONY: $(RTE_OUTPUT)/$(distdir)
$(RTE_OUTPUT)/$(distdir):
	for d in $(DIST_DIRS) $(EXTRA_DIRS); do \
		mkdir -p $(RTE_OUTPUT)/$(distdir)/$$d; \
	done
	for f in $(DISTFILES); do \
		cp $$f $(RTE_OUTPUT)/$(distdir)/$$f; \
	done
	echo $(version) >$(RTE_OUTPUT)/$(distdir)/.version

$(RTE_OUTPUT)/$(distdir).tar.xz: $(RTE_OUTPUT)/$(distdir) $(DISTFILES)
	tar -C $(RTE_OUTPUT) -c $(distdir) | xz > $@
	$(RM) -r $(RTE_OUTPUT)/$(distdir)

.PHONY: dist
dist: $(RTE_OUTPUT)/$(distdir).tar.xz

.PHONY: distcheck
distcheck: dist
	@if [ -d $(RTE_OUTPUT)/_dist ]; then \
		chmod -R u+w $(RTE_OUTPUT)/_dist && $(RM) -r $(RTE_OUTPUT)/_dist; \
	fi
	@mkdir -p $(RTE_OUTPUT)/_dist
	@xz -cd $(RTE_OUTPUT)/$(distdir).tar.xz | tar -x -C $(RTE_OUTPUT)/_dist
	@chmod -R a-w $(RTE_OUTPUT)/_dist
	@$(RM) -r $(RTE_OUTPUT)/_build
	@mkdir -p $(RTE_OUTPUT)/_build
	@$(MAKE) -f $(RTE_OUTPUT)/_dist/$(distdir)/Makefile O=$(RTE_OUTPUT)/_build -C $(RTE_OUTPUT)/_dist/$(distdir)
	@$(MAKE) -f $(RTE_OUTPUT)/_dist/$(distdir)/Makefile O=$(RTE_OUTPUT)/_build -C $(RTE_OUTPUT)/_dist/$(distdir) clean
	@find $(RTE_OUTPUT)/_build -type f -name _postclean -exec rm -f {} +
	@if ! find $(RTE_OUTPUT)/_build -depth -type d -exec rmdir {} + &>/dev/null; then \
		printf "Files remain in build directory after build:\n"; \
		find $(RTE_OUTPUT)/_build ! -type d -print; \
		false; \
	fi
	@chmod -R u+w $(RTE_OUTPUT)/_dist
	@$(RM) -r $(RTE_OUTPUT)/_dist
	@echo "*** Package $(RTE_OUTPUT)/$(distdir).tar.xz is ready for distribution."

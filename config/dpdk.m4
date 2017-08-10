# Userspace Software iWARP library for DPDK
#
# Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
#
# Copyright (c) 2016-2017, University of New Hampshire
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

# URDMA_LIB_DPDK
# --------------
# Checks that we have DPDK, and optionally checks that the version is at
# least the one requested. Note that this macro will abort if DPDK is
# not found; fixing this would take more effort than it is worth.
AC_DEFUN([URDMA_LIB_DPDK],
[
AC_ARG_VAR([RTE_SDK], [Location of DPDK SDK installation])
AC_ARG_VAR([RTE_TARGET], [DPDK target system and toolchain])
if test ${RTE_SDK}x = x; then
	AC_MSG_ERROR([urdma requires DPDK.  Set RTE_SDK to the DPDK install location])
fi
if test ${RTE_TARGET}x = x; then
	AC_MSG_ERROR([urdma requires DPDK.  Set RTE_TARGET to the DPDK compilation target])
fi

DPDK_CPPFLAGS="-I${RTE_SDK}/${RTE_TARGET}/include"
AC_SUBST([DPDK_CPPFLAGS])
DPDK_LDFLAGS="-L${RTE_SDK}/${RTE_TARGET}/lib"
AC_SUBST([DPDK_LDFLAGS])

AC_CACHE_CHECK([for DPDK machine compiler flags],
[urdma_cv_cflags_machine], [cat >conftest.make <<_EOF
SHELL = /bin/sh
include \$(RTE_SDK)/mk/rte.vars.mk
.PHONY: all
all:
	@echo 'MACHINE_CFLAGS=\$(MACHINE_CFLAGS)'
_EOF
result=`${MAKE-make} -f conftest.make 2>/dev/null | grep MACHINE_CFLAGS=`
AS_CASE([$result],
	[MACHINE_CFLAGS=*],
	[urdma_cv_cflags_machine=`printf %s "$result" | sed -e 's/^MACHINE_CFLAGS=//'`],
	[urdma_cv_cflags_machine="not found"])
AS_UNSET([result])
rm -f conftest.make])
if test "x$urdma_cv_cflags_machine" = "xnot found"; then
	AC_MSG_ERROR([Could not detect DPDK compiler flags; check your DPDK installation])
fi
MACHINE_CFLAGS=$urdma_cv_cflags_machine
AC_SUBST([MACHINE_CFLAGS])

old_CFLAGS="${CFLAGS}"
old_CPPFLAGS="${CPPFLAGS}"
old_LDFLAGS="${LDFLAGS}"
CFLAGS="${CFLAGS} ${MACHINE_CFLAGS}"
CPPFLAGS="${CPPFLAGS} ${DPDK_CPPFLAGS}"
LDFLAGS="${CPPFLAGS} ${DPDK_LDFLAGS}"
AC_CHECK_HEADERS([rte_ethdev.h], [],
[AC_MSG_ERROR([urdma requires DPDK >= 16.07])])

old_LIBS="${LIBS}"
LIBS="-ldpdk ${LIBS}"
AC_MSG_CHECKING([for DPDK 16.07 built as shared libraries])
AC_LINK_IFELSE([AC_LANG_PROGRAM(
[[#include <rte_eal.h>
 #include <rte_ethdev.h>]],
[[int main(int argc, char *argv[]) {
	struct rte_eth_dev_info info;
	rte_eal_init(argc, argv);
	info.nb_rx_queues = 1;
	return 0;
}]])],
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
	[AC_MSG_ERROR([urdma requires DPDK >= 16.07])])


LIBS=${old_LIBS}
DPDK_LIBS="-Wl,--whole-archive,-ldpdk,--no-whole-archive"
AC_SUBST([DPDK_LIBS])

CFLAGS="${old_CFLAGS}"
CPPFLAGS="${old_CPPFLAGS}"
LDFLAGS="${old_LDFLAGS}"
]) # URDMA_LIB_DPDK

# DPDK_CHECK_FUNC(FUNCTION, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# -------------------------------------------------------------------
# Like AC_CHECK_FUNC, but add DPDK_LIBS, DPDK_CFLAGS, DPDK_CPPFLAGS, and
# DPDK_LDFLAGS to their respective variables first and restore them
# afterward.
AC_DEFUN([DPDK_CHECK_FUNC],
[
_dpdkcf_old_CFLAGS="${CFLAGS}"
_dpdkcf_old_CPPFLAGS="${CPPFLAGS}"
_dpdkcf_old_LDFLAGS="${LDFLAGS}"
_dpdkcf_old_LIBS="${LIBS}"

CFLAGS="${CFLAGS} ${MACHINE_CFLAGS}"
CPPFLAGS="${CPPFLAGS} ${DPDK_CPPFLAGS}"
LDFLAGS="${CPPFLAGS} ${DPDK_LDFLAGS}"
LIBS="${DPDK_LIBS} ${LIBS}"

m4_case([$#],
	[1], [AC_CHECK_FUNC([$1])],
	[2], [AC_CHECK_FUNC([$1], [$2])],
	[3], [AC_CHECK_FUNC([$1], [$2], [$3])],
	[m4_fatal([DPDK_CHECK_FUNC requires 1-3 arguments])])

CFLAGS="${_dpdkcf_old_CFLAGS}"
CPPFLAGS="${_dpdkcf_old_CPPFLAGS}"
LDFLAGS="${_dpdkcf_old_LDFLAGS}"
LIBS=${_dpdkcf_old_LIBS}
]) # DPDK_CHECK_FUNC

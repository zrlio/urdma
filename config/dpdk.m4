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

# URDMA_LIB_DPDK([VERSION])
# -------------------------
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

AC_SUBST([DPDK_CPPFLAGS], ["-I${RTE_SDK}/${RTE_TARGET}/include"])
AC_SUBST([DPDK_LDFLAGS], ["-L${RTE_SDK}/${RTE_TARGET}/lib"])
AC_SUBST([DPDK_LIBS], ["-Wl,--whole-archive,-ldpdk,--no-whole-archive -ldpdk"])

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
DPDK_CFLAGS=$urdma_cv_cflags_machine
AC_SUBST([DPDK_CFLAGS])

old_CFLAGS="${CFLAGS}"
old_CPPFLAGS="${CPPFLAGS}"
old_LDFLAGS="${LDFLAGS}"
old_LIBS="${LIBS}"
CFLAGS="${CFLAGS} ${DPDK_CFLAGS}"
CPPFLAGS="${CPPFLAGS} ${DPDK_CPPFLAGS}"
LDFLAGS="${LDFLAGS} ${DPDK_LDFLAGS}"
LIBS="${DPDK_LIBS} ${LIBS}"

AC_CHECK_HEADERS([rte_version.h], [],
		 [AC_MSG_ERROR([urdma requires DPDK >= $1])])

AC_CACHE_CHECK([for DPDK release version m4_if(m4_eval([$# >= 1]), 1, [at least $1])],
       [urdma_cv_librelver_dpdk],
       [[dummy=if$$
	cat <<_URDMA_EOF > $dummy.c
#include <rte_version.h>
#if defined(RTE_VER_YEAR) && defined(RTE_VER_MONTH)
dpdk_major_version RTE_VER_YEAR
dpdk_minor_version RTE_VER_MONTH
#elif defined(RTE_VER_MAJOR) && defined(RTE_VER_MINOR)
dpdk_major_version RTE_VER_MAJOR
dpdk_minor_version RTE_VER_MINOR
#else
undefined
#endif
_URDMA_EOF
	_dpdk_out=`$CC $CPPFLAGS -E $dummy.c 2> /dev/null | tail -n 2 >$dummy.i`
	_dpdk_major=`grep '^dpdk_major_version' $dummy.i | cut -d' ' -f2`
	_dpdk_minor=`grep '^dpdk_minor' $dummy.i | cut -d' ' -f2`
	if test $_dpdk_major -lt 16; then
		_fmt="%d.%d"
	else
		_fmt="%d.%02d"
	fi
	urdma_cv_librelver_dpdk=`printf "${_fmt}" ${_dpdk_major} ${_dpdk_minor}`
	rm -f $dummy.c $dummy.i]])
m4_if(m4_eval([$# >= 1]), 1,
[case $urdma_cv_librelver_dpdk in #(
undefined) AC_MSG_ERROR([urdma requires DPDK >= $1]) ;; #(
*) AX_COMPARE_VERSION([$1], [le], [$urdma_cv_librelver_dpdk], [],
		      [AC_MSG_ERROR([urdma requires DPDK >= $1])])
esac
])

CFLAGS="${old_CFLAGS}"
CPPFLAGS="${old_CPPFLAGS}"
LDFLAGS="${old_LDFLAGS}"
LIBS=${old_LIBS}
]) # URDMA_LIB_DPDK

# _WITH_DPDK_FLAGS(PROGRAM)
# -------------------------
# Runs the m4 code inside with DPDK_LIBS, DPDK_CFLAGS, DPDK_CPPFLAGS,
# and DPDK_LDFLAGS set to their respective variables first and restores
# them afterward.
AC_DEFUN([_WITH_DPDK_FLAGS],
[
_dpdk_old_CFLAGS="${CFLAGS}"
_dpdk_old_CPPFLAGS="${CPPFLAGS}"
_dpdk_old_LDFLAGS="${LDFLAGS}"
_dpdk_old_LIBS="${LIBS}"

CFLAGS="${CFLAGS} ${DPDK_CFLAGS}"
CPPFLAGS="${CPPFLAGS} ${DPDK_CPPFLAGS}"
LDFLAGS="${LDFLAGS} ${DPDK_LDFLAGS}"
LIBS="${DPDK_LIBS} ${LIBS}"

$1

CFLAGS="${_dpdk_old_CFLAGS}"
CPPFLAGS="${_dpdk_old_CPPFLAGS}"
LDFLAGS="${_dpdk_old_LDFLAGS}"
LIBS=${_dpdk_old_LIBS}
]) _WITH_DPDK_FLAGS

# DPDK_CHECK_FUNC(FUNCTION, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# -------------------------------------------------------------------
# Like AC_CHECK_FUNC, but add DPDK_LIBS, DPDK_CFLAGS, DPDK_CPPFLAGS, and
# DPDK_LDFLAGS to their respective variables first and restore them
# afterward.
AC_DEFUN([DPDK_CHECK_FUNCS], [
_WITH_DPDK_FLAGS([
m4_case([$#],
	[1], [AC_CHECK_FUNCS([$1])],
	[2], [AC_CHECK_FUNCS([$1], [$2])],
	[3], [AC_CHECK_FUNCS([$1], [$2], [$3])],
	[m4_fatal([DPDK_CHECK_FUNCS requires 1-3 arguments])])
])]) # DPDK_CHECK_FUNCS

# _DPDK_FUNC_RING_BURST
# ---------------------
# Private internal macro used by DPDK_FUNC_RTE_RING_DEQUEUE_BURST and
# DPDK_FUNC_RTE_RING_ENQUEUE_BURST. Takes a single argument with the
# function to test.
AC_DEFUN([_DPDK_FUNC_RING_BURST],
[_WITH_DPDK_FLAGS([
dnl cv_name will expand to the correct cache variable name throughout
dnl the text of this macro; it is undefined at the end.
m4_define([cv_name], [dpdk_cv_func_which_$1])
AC_CACHE_CHECK([how many arguments $1 takes],
	cv_name,
	[AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <rte_ring.h>]],
					 [$1@{:@@:}@;])],
	[[# No-argument case is invalid and means we didn't find a prototype]]
	[cv_name=no],
	[AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <rte_ring.h>]],
					 [$1@{:@NULL, NULL, 1, NULL@:}@;])],
	[cv_name=4],
	[AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <rte_ring.h>]],
					 [$1@{:@NULL, NULL, 1@:}@;])],
	[cv_name=3],
	[cv_name=no])])])])
m4_undefine([cv_name])
])]) # _DPDK_FUNC_RING_BURST

# DPDK_FUNC_RTE_RING_DEQUEUE_BURST
# --------------------------------
# Checks how many arguments rte_ring_dequeue_burst() takes. Defines
# HAVE_RTE_RING_DEQUEUE_BURST if the function exists, and defines one of
# HAVE_FUNC_RTE_RING_DEQUEUE_BURST_3 or HAVE_FUNC_RTE_RING_DEQUEUE_BURST_4
# depending on whether or not this function takes the fourth argument
# added in DPDK 17.05. This macro defines the cache variable
# dpdk_cv_func_which_rte_ring_dequeue_burst to "no" or the number of
# arguments it takes.
AC_DEFUN([DPDK_FUNC_RTE_RING_DEQUEUE_BURST],
[
_DPDK_FUNC_RING_BURST([rte_ring_dequeue_burst])
if test "x$dpdk_cv_func_which_rte_ring_dequeue_burst" != "xno"; then
	AC_DEFINE([HAVE_RTE_RING_DEQUEUE_BURST], [1],
		  [Define to 1 if DPDK provides rte_ring_dequeue_burst])
fi
if test "x$dpdk_cv_func_which_rte_ring_dequeue_burst" = "x4"; then
	AC_DEFINE([HAVE_FUNC_RTE_RING_DEQUEUE_BURST_4], [1],
		  [Define to 1 if rte_ring_dequeue_burst takes 4 arguments])
elif test "x$dpdk_cv_func_which_rte_ring_dequeue_burst" = "x3"; then
	AC_DEFINE([HAVE_FUNC_RTE_RING_DEQUEUE_BURST_3], [1],
		  [Define to 1 if rte_ring_dequeue_burst takes 3 arguments])
fi
]) # DPDK_FUNC_RTE_RING_DEQUEUE_BURST

# DPDK_FUNC_RTE_RING_ENQUEUE_BURST
# --------------------------------
# Checks how many arguments rte_ring_enqueue_burst() takes. Defines
# HAVE_RTE_RING_ENQUEUE_BURST if the function exists, and defines one of
# HAVE_FUNC_RTE_RING_ENQUEUE_BURST_3 or HAVE_FUNC_RTE_RING_ENQUEUE_BURST_4
# depending on whether or not this function takes the fourth argument
# added in DPDK 17.05. This macro defines the cache variable
# dpdk_cv_func_which_rte_ring_dequeue_burst to "no" or the number of
# arguments it takes.
AC_DEFUN([DPDK_FUNC_RTE_RING_ENQUEUE_BURST],
[
_DPDK_FUNC_RING_BURST([rte_ring_enqueue_burst])
if test "x$dpdk_cv_func_which_rte_ring_enqueue_burst" != "xno"; then
	AC_DEFINE([HAVE_RTE_RING_ENQUEUE_BURST], [1],
		  [Define to 1 if DPDK provides rte_ring_enqueue_burst])
fi
if test "x$dpdk_cv_func_which_rte_ring_enqueue_burst" = "x4"; then
	AC_DEFINE([HAVE_FUNC_RTE_RING_ENQUEUE_BURST_4], [1],
		  [Define to 1 if rte_ring_enqueue_burst takes 4 arguments])
elif test "x$dpdk_cv_func_which_rte_ring_enqueue_burst" = "x3"; then
	AC_DEFINE([HAVE_FUNC_RTE_RING_ENQUEUE_BURST_3], [1],
		  [Define to 1 if rte_ring_enqueue_burst takes 3 arguments])
fi
]) # DPDK_FUNC_RTE_RING_ENQUEUE_BURST

# DPDK_CHECK_HEADERS(HEADER-FILE, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND], [INCLUDES])
# -------------------------------------------------------------------------------------
# Like AC_CHECK_HEADERS, but add DPDK_LIBS, DPDK_CFLAGS, DPDK_CPPFLAGS, and
# DPDK_LDFLAGS to their respective variables first and restore them
# afterward.
AC_DEFUN([DPDK_CHECK_HEADERS], [
_WITH_DPDK_FLAGS([
m4_case([$#],
	[1], [AC_CHECK_HEADERS([$1])],
	[2], [AC_CHECK_HEADERS([$1], [$2])],
	[3], [AC_CHECK_HEADERS([$1], [$2], [$3])],
	[4], [AC_CHECK_HEADERS([$1], [$2], [$3], [$4])],
	[m4_fatal([DPDK_CHECK_HEADERS requires 1-4 arguments])])
])]) # DPDK_CHECK_HEADERS

# DPDK_CHECK_SIZEOF_PORT_ID()
# -------------------------------------------------------------------------------------
# Set HAVE_UINT16_T_PORT_ID if port_id arguments are uint16_t instead of uint8_t.
AC_DEFUN([DPDK_CHECK_SIZEOF_PORT_ID], [
_WITH_DPDK_FLAGS([
CFLAGS="${CFLAGS} -Werror"
AC_CACHE_CHECK([if port_id is uint16_t],
	       [urdma_cv_decltype_port_id_uint16_t],
	       [AC_LINK_IFELSE([AC_LANG_PROGRAM(
			[[#include <rte_ethdev.h>
			  #include <stdint.h>]],
			[[int main(void) { uint16_t x; rte_eth_dev_attach(NULL, &x); return 0; }]])],
			[urdma_cv_decltype_port_id_uint16_t=yes],
			[urdma_cv_decltype_port_id_uint16_t=no])])
if test "x$urdma_cv_decltype_port_id_uint16_t" = xyes; then
	AC_DEFINE([HAVE_UINT16_T_PORT_ID], [1],
		  [Define to 1 if DPDK port_id arguments are uint16_t])
fi
])]) # DPDK_CHECK_SIZEOF_PORT_ID

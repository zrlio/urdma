# Userspace Software iWARP library for DPDK
#
# Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
#
# Copyright (c) 2018, University of New Hampshire
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

# _URDMA_FUNC_VERBS_INIT_AND_ALLOC_CONTEXT()
# -----------------------------------------
# Checks how many arguments the verbs_init_and_alloc_context macro
# takes. Defines HAVE_VERBS_INIT_AND_ALLOC_CONTEXT to the number of
# arguments that the macro takes if it exists; otherwise, aborts.
AC_DEFUN([_URDMA_FUNC_VERBS_INIT_AND_ALLOC_CONTEXT],
[
AC_CACHE_CHECK([number of arguments verbs_init_and_alloc_context takes],
	[dpdk_cv_func_verbs_init_and_alloc_context],
	[old_CPPFLAGS="${CPPFLAGS}"
	CPPFLAGS="-I${srcdir} -I${srcdir}/rdma-core/${ibverbs_pabi_version} ${CPPFLAGS}"
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <infiniband/driver.h>]],
					 [verbs_init_and_alloc_context@{:@@:}@;])],
	[[# No-argument case is invalid and means we didn't find a prototype]]
	[dpdk_cv_func_verbs_init_and_alloc_context=no],
	[AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <infiniband/driver.h>]],
					 [[struct foo { struct verbs_context bar; } *baz; verbs_init_and_alloc_context@{:@NULL, NULL, baz, bar, 0@:}@;]])],
	[dpdk_cv_func_verbs_init_and_alloc_context=5],
	[AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <infiniband/driver.h>]],
					 [[struct foo { struct verbs_context bar; } *baz; verbs_init_and_alloc_context@{:@NULL, NULL, baz, bar@:}@;]])],
	[dpdk_cv_func_verbs_init_and_alloc_context=4],
	[dpdk_cv_func_verbs_init_and_alloc_context=no])])])])
if test "x$dpdk_cv_func_verbs_init_and_alloc_context" = "xno"; then
	AC_MSG_ERROR([Colud not determine; check your rdma-core installation])
else
	AC_DEFINE_UNQUOTED([HAVE_VERBS_INIT_AND_ALLOC_CONTEXT],
		           [${dpdk_cv_func_verbs_init_and_alloc_context}],
			   [Define to number of arguments taken by verbs_init_and_alloc_context])
	CPPFLAGS="${old_CPPFLAGS}"
fi
]) # _URDMA_FUNC_VERBS_INIT_AND_ALLOC_CONTEXT

# URDMA_LIB_IBVERBS_PROV([MIN_VERSION], [MAX_VERSION])
# -------------------------
# Checks that we have rdma-core, and checks that the version is within
# the supported range.
# Note that this macro will abort if a suitable libibverbs is
# not found; fixing this would take more effort than it is worth.
# Defines the C preprocessor symbol IBVERBS_PABI_VERSION to the version
# of rdma-core that was found.
AC_DEFUN([URDMA_LIB_IBVERBS_PROV],
[
ibverbs_pabi_version=
min=$1
max=$2
for pabi_version in `seq "${max}" -1 "${min}"`
do
	AC_SEARCH_LIBS([verbs_register_driver_${pabi_version}],
		       [ibverbs],
		       [ibverbs_pabi_version=${pabi_version}; break], [])
done

if test "x$ibverbs_pabi_version" = x; then
       AC_MSG_ERROR([urdma requires rdma-core >= MIN_VERSION])
fi

AC_DEFINE_UNQUOTED([IBVERBS_PABI_VERSION], [${ibverbs_pabi_version}],
		   [Define to rdma-core private ABI version])
AC_SUBST([ibverbs_pabi_version])

if test $ibverbs_pabi_version -ge 17; then
	_URDMA_FUNC_VERBS_INIT_AND_ALLOC_CONTEXT
fi

IBV_DEVICE_LIBRARY_EXTENSION=rdmav${ibverbs_pabi_version}
AC_SUBST([IBV_DEVICE_LIBRARY_EXTENSION])
]) # URDMA_LIB_IBVERBS_PROV

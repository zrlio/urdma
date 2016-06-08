/* options.c */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <pam@zurich.ibm.com>
 *
 * Copyright (c) 2016, IBM Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted provided that the following
 *   conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of IBM nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>

#include "options.h"

const char *
option_string(void)
{
	return "[-f|--nvm-file <nvm-file>] ";
}

int
parse_options(int argc, char **argv, struct server_options *options)
{
	static const struct option longopts[] = {
		{ .name = "help", .has_arg = no_argument,
			.flag = NULL, .val = 'h' },
		{ .name = "nvm-file", .has_arg = required_argument,
			.flag = NULL, .val = 'f' },
		{ 0 },
	};

	int ch;

	memset(options, 0, sizeof(*options));
	while ((ch = getopt_long(argc, argv,
					"h" /* --help */
					"f:" /* --nvm-file */
					, longopts, NULL)) != -1) {
		switch (ch) {
		case 'h':
			fprintf(stderr, "-h, --help: Print this help message\n");
			fprintf(stderr, "-f, --nvm-file: Back storage with this file\n");
			exit(EXIT_SUCCESS);
			break;
		case 'f':
			options->nvm_fn = optarg;
			break;
		default:
			rte_exit(EXIT_FAILURE, "Unexpected option -%c\n", ch);
		}
	}

	return optind - 1;
}

/* options.c */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <pam@zurich.ibm.com>
 *
 * Copyright (c) 2016, IBM Corporation
 * Copyright (c) 2016, University of New Hampshire
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_config.h>
#include <rte_common.h>

#include "options.h"

const char *
option_string(void)
{
	return "[-i input|--input <input-file>] [-o output|--output <output-file>] ";
}

int
parse_options(int argc, char **argv, struct client_options *options)
{
	static const struct option longopts[] = {
		{ .name = "help", .has_arg = no_argument,
			.flag = NULL, .val = 'h' },
		{ .name = "input", .has_arg = required_argument,
			.flag = NULL, .val = 'i' },
		{ .name = "output", .has_arg = required_argument,
			.flag = NULL, .val = 'o' },
		{ 0 },
	};

	int ch;

	memset(options, 0, sizeof(*options));
	while ((ch = getopt_long(argc, argv,
					"h" /* --help */
					"i:" /* --input */
					"o:" /* --output */
					, longopts, NULL)) != -1) {
		switch (ch) {
		case 'h':
			fprintf(stderr, "-h, --help: Print this help message\n");
			fprintf(stderr, "-i, --input: File with memcached commands\n");
			fprintf(stderr, "-o, --output: File with memcached responses\n");
			break;
		case 'i':
			options->command_fn = optarg;
			options->command_fp = fopen(options->command_fn, "r");
			if (!options->command_fp) {
				rte_exit(EXIT_FAILURE, "Open %s for reading: %s\n",
						options->command_fn,
						strerror(errno));
			}
			break;
		case 'o':
			options->output_fn = optarg;
			if (strcmp(options->output_fn, "-") == 0) {
				options->output_fp = stdout;
			} else {
				options->output_fp = fopen(options->output_fn, "w");
			}
			if (!options->output_fp) {
				rte_exit(EXIT_FAILURE, "Open %s for writing: %s\n",
						options->output_fn,
						strerror(errno));
			}
			break;
		default:
			rte_exit(EXIT_FAILURE, "Unexpected option -%c\n", ch);
		}
	}

	if (!options->command_fp) {
		fprintf(stderr, "No input file specified.\n");
		return -1;
	}

	return optind - 1;
}

/* mkkvstore.c */

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

/* Creates an empty key-value store. */

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <math.h>

#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_jhash.h>

#include "kvstore_storage.h"

enum { DEFAULT_FILE_SIZE = 1073741824 };

enum { DEFAULT_PAGE_SIZE = 4096 };

struct mkkvstore_options {
	unsigned long bucket_count;
	unsigned long slot_count;
	unsigned long file_size;
	unsigned long page_size;
	unsigned long long value_size;
};

static unsigned long
get_page_size(void)
{
	long pagesize;

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0) {
		pagesize = DEFAULT_PAGE_SIZE;
	}
	return pagesize;
} /* get_pagesize */

static bool
does_fit(struct mkkvstore_options *options)
{
	return 1 + ceil((double)sizeof(struct store_bucket)
				* options->bucket_count / options->page_size)
			+ ceil(options->slot_count / (8.0 * options->page_size))
			+ ceil(options->slot_count * options->value_size
					/ options->page_size)
			<= options->file_size / options->page_size;
} /* does_fit */

static unsigned long
max_slot_count(unsigned long bucket_count, unsigned long page_size,
		unsigned long total_page_count, unsigned long long value_size)
{
	double bytes_per_bucket;
	double pages_per_slot;
	unsigned long remaining_pages;
	unsigned long res;

	assert(value_size % page_size == 0);
	bytes_per_bucket = (double)sizeof(struct store_bucket);
	remaining_pages = total_page_count - 1
		- ceil(bytes_per_bucket * bucket_count / page_size);
	pages_per_slot = 1.0 / (8 * page_size)
		+ value_size / page_size;
	res = remaining_pages / pages_per_slot;

	return res;
} /* max_slot_count */

static int
write_header(int fd, const struct mkkvstore_options *options,
		struct store_header *header)
{
	ssize_t header_size, ret;

	header->magic = 0x1B4D;
	header->version = 0;
	header->main_bucket_count = options->bucket_count;
	header->page_size = options->page_size;
	header->reserved_12 = 0;
	header->slot_count = options->slot_count;
	header->value_max_size = options->value_size;

	header_size = sizeof(*header);
	ret = pwrite(fd, header, header_size, 0);
	return (ret < header_size) ? -1 : 0;
} /* write_header */

static void
usage(int exit_status)
{
	fprintf(stderr, "Usage: mkkvstore [options] <file>\n\n");
	fprintf(stderr, "-b, --bucket-count: Number of hash table buckets\n");
	fprintf(stderr, "-c, --slot-count: Number of data slots\n");
	fprintf(stderr, "-p, --page-size: Alignment of sections\n");
	fprintf(stderr, "-s, --file-size: Total size of file in bytes\n");
	fprintf(stderr, "-v, --value-size: Maximum value size\n");
	exit(exit_status);
} /* usage */

static void
parse_options(int argc, char **argv, struct mkkvstore_options *options)
{
	static const struct option longopts[] = {
		{ .name = "bucket-count", .has_arg = required_argument,
			.flag = NULL, .val = 'b' },
		{ .name = "slot-count", .has_arg = required_argument,
			.flag = NULL, .val = 'c' },
		{ .name = "help", .has_arg = no_argument,
			.flag = NULL, .val = 'h' },
		{ .name = "page-size", .has_arg = required_argument,
			.flag = NULL, .val = 'p' },
		{ .name = "file-size", .has_arg = required_argument,
			.flag = NULL, .val = 's' },
		{ .name = "value-size", .has_arg = required_argument,
			.flag = NULL, .val = 'v' },
		{ 0 },
	};

	char *endch;
	int ch;

	memset(options, 0, sizeof(*options));
	options->page_size = get_page_size();
	options->file_size = DEFAULT_FILE_SIZE;
	options->value_size = KVSTORE_VALUE_LEN_MAX;
	while ((ch = getopt_long(argc, argv,
					"b:" /* --bucket-count */
					"c:" /* --slot-count */
					"h" /* --help */
					"p:" /* --page-size */
					"s:" /* --file-size */
					"v:" /* --value-size */
					, longopts, NULL)) != -1) {
		switch (ch) {
		case 'b':
			errno = 0;
			options->bucket_count = strtoul(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0' || !options->bucket_count) {
				fprintf(stderr, "Invalid bucket count \"%s\"\n",
						optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'c':
			errno = 0;
			options->slot_count = strtoul(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0' || !options->slot_count) {
				fprintf(stderr, "Invalid slot count \"%s\"\n",
						optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		case 'p':
			errno = 0;
			options->page_size = strtoul(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0' || !options->page_size) {
				fprintf(stderr, "Invalid page size \"%s\"\n",
						optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 's':
			errno = 0;
			options->file_size = strtoul(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0' || !options->file_size) {
				fprintf(stderr, "Invalid file size \"%s\"\n",
						optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'v':
			errno = 0;
			options->value_size = strtoul(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0' || !options->value_size
					|| options->value_size
					> KVSTORE_VALUE_LEN_MAX) {
				fprintf(stderr, "Invalid value size \"%s\"\n",
						optarg);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			rte_exit(EXIT_FAILURE, "Unexpected option -%c\n", ch);
		}
	}

	if (options->slot_count == 0 && options->bucket_count == 0) {
		for (options->bucket_count = 1024;
				options->bucket_count < (1UL << 31);
				options->bucket_count <<= 1) {
			options->slot_count = max_slot_count(
					options->bucket_count,
					options->page_size,
					options->file_size/options->page_size,
					options->value_size);
			if (options->slot_count < options->bucket_count) {
				break;
			}
		}
	} else if (options->slot_count > 0 && options->bucket_count == 0) {
		options->bucket_count = 1;
		while (options->bucket_count < options->slot_count) {
			options->bucket_count <<= 1;
		}
	} else if (options->bucket_count > 0 && options->slot_count == 0) {
		options->slot_count = max_slot_count(
				options->bucket_count,
				options->page_size,
				options->file_size / options->page_size,
				options->value_size);
	}

	if (options->slot_count >= options->bucket_count
			|| !does_fit(options)) {
		fprintf(stderr, "Constraint violation!\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "File size: %lu\n", options->file_size);
	fprintf(stderr, "Main bucket count: %lu\n", options->bucket_count);
	fprintf(stderr, "Page size: %lu\n", options->page_size);
	fprintf(stderr, "Slot count: %lu\n", options->slot_count);
	fprintf(stderr, "Value max size: %llu\n", options->value_size);
} /* parse_options */

int
main(int argc, char *argv[])
{
	struct mkkvstore_options options;
	struct store_header header;
	int fd, ret;

	parse_options(argc, argv, &options);
	argv[optind - 1] = argv[0];
	argc -= optind - 1;
	argv += optind - 1;

	if (argc != 2) {
		usage(EXIT_FAILURE);
	}

	fd = open(argv[1], O_WRONLY|O_CREAT|O_EXCL, 0660);
	if (fd < 0) {
		fprintf(stderr, "Open %s for writing: %s\n",
				argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (ftruncate(fd, options.file_size) < 0) {
		fprintf(stderr, "Expand %s to %lu bytes: %s\n",
				argv[1], options.file_size,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	write_header(fd, &options, &header);

	ret = EXIT_SUCCESS;

	close(fd);
	return ret;
} /* main */

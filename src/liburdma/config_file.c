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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <stddef.h>

#include <linkhash.h>
#include <json_object.h>
#include <json_tokener.h>
#include <stdio.h>
#include <sys/prctl.h>

#include "config_file.h"
#include "util.h"

static int
analyze_ports(struct json_object *root, struct usiw_config *config)
{
	struct json_object *ports, *port, *ipv4;
	int i;

	if (!json_object_object_get_ex(root, "ports", &ports)) {
		fprintf(stderr, "Configuration error: JSON root object has no \"ports\" field\n");
		return -EINVAL;
	}

	if (!json_object_is_type(ports, json_type_array)) {
		fprintf(stderr, "Configuration error: \"ports\" field is not an array\n");
		return -EINVAL;
	}

	config->port_count = json_object_array_length(ports);
	config->port_config = calloc(config->port_count, sizeof(*config->port_config));
	if (!config->port_config) {
		return -ENOMEM;
	}
	for (i = 0; i < config->port_count; i++) {
		port = json_object_array_get_idx(ports, i);
		if (!json_object_is_type(port, json_type_object)) {
			fprintf(stderr, "Configuration error: port array element %d is not hash\n",
					i);
			return -EINVAL;
		}
		if (!json_object_object_get_ex(port, "ipv4_address", &ipv4)) {
			fprintf(stderr, "Configuration error: port has no \"ipv4_address\" field\n");
			return -EINVAL;
		}
		if (!json_object_is_type(ipv4, json_type_string)) {
			fprintf(stderr, "Configuration error: ipv4_address is not string\n");
			return -EINVAL;
		}
		strncpy(config->port_config[i].ipv4_address,
				json_object_get_string(ipv4),
				ipv4_addr_len_max);
	}

	return 0;
} /* analyze_ports */

static char *
get_argv0(void)
{
	enum { prctl_name_size = 16 };
	char name[prctl_name_size];

	if (prctl(PR_GET_NAME, (uintptr_t)name, 0, 0, 0) < 0) {
		return strdup("dummy");
	}
	return strdup(name);
} /* get_argv0 */

static int
analyze_eal_args(struct json_object *root, struct usiw_config *config)
{
	struct json_object *args;
	int key_len, len, i, ret;

	if (!json_object_object_get_ex(root, "eal_args", &args)) {
		/* eal_args are optional; we accept defaults if this field is
		 * not present */
		config->eal_argc = 1;
		config->eal_argv = calloc(2, sizeof(*config->eal_argv));
		config->eal_argv[0] = get_argv0();
		return config->eal_argv ? 0 : -ENOMEM;
	}

	if (!json_object_is_type(args, json_type_object)) {
		fprintf(stderr, "Configuration error: \"eal_args\" field is not a hash\n");
		return -EINVAL;
	}

	len = json_object_object_length(args);
	config->eal_argv = calloc(2 * (len + 1),
			sizeof(*config->eal_argv));
	if (!config->eal_argv) {
		return -ENOMEM;
	}
	config->eal_argv[0] = get_argv0();
	if (!config->eal_argv[0]) {
		i = 0;
		goto free_args;
	}

	i = 1;
	json_object_object_foreach(args, key, value) {
		key_len = strlen(key);
		switch (json_object_get_type(value)) {
		case json_type_boolean:
			if (json_object_get_boolean(value)) {
				ret = asprintf(&config->eal_argv[i++], "-%s%s",
						key_len > 1 ? "-" : "",
						key);
				if (ret < 0) {
					goto free_args;
				}
			}
			break;
		case json_type_string:
			if (key_len > 1) {
				ret = asprintf(&config->eal_argv[i++], "--%s=%s",
						key,
						json_object_get_string(value));
				if (ret < 0) {
					goto free_args;
				}
			} else {
				ret = asprintf(&config->eal_argv[i++], "-%s",
						key);
				if (ret < 0) {
					goto free_args;
				}
				ret = asprintf(&config->eal_argv[i++], "%s",
						json_object_get_string(value));
				if (ret < 0) {
					goto free_args;
				}
			}
			break;
		case json_type_int:
			if (key_len > 1) {
				ret = asprintf(&config->eal_argv[i++], "--%s=%" PRId64,
						key,
						json_object_get_int64(value));
				if (ret < 0) {
					goto free_args;
				}
			} else {
				ret = asprintf(&config->eal_argv[i++], "-%s",
						key);
				if (ret < 0) {
					goto free_args;
				}
				ret = asprintf(&config->eal_argv[i++], "%" PRId64,
						json_object_get_int64(value));
				if (ret < 0) {
					goto free_args;
				}
			}
			break;
		case json_type_double:
			if (key_len > 1) {
				ret = asprintf(&config->eal_argv[i++], "--%s=%.12f",
						key,
						json_object_get_double(value));
				if (ret < 0) {
					goto free_args;
				}
			} else {
				ret = asprintf(&config->eal_argv[i++], "-%s",
						key);
				if (ret < 0) {
					goto free_args;
				}
				ret = asprintf(&config->eal_argv[i++], "%.12f",
						json_object_get_double(value));
				if (ret < 0) {
					goto free_args;
				}
			}
			break;
		default:
			config->eal_argc = i;
			errno = EINVAL;
			goto free_args;
		}
	}
	config->eal_argc = i;
	config->eal_argv[i] = NULL;

	config->freelist = malloc(2 * (len + 1) * sizeof(*config->freelist));
	if (config->freelist) {
		memcpy(config->freelist, config->eal_argv,
				2 * (len + 1) * sizeof(*config->freelist));
	}

	return 0;

free_args:
	for (len = i, i = 0; i < len; ++i) {
		free(config->eal_argv[i]);
	}
	free(config->eal_argv);
	return -errno;
} /* analyze_eal_args */

static int
analyze_root(struct json_object *root, struct usiw_config *config)
{
	int ret;

	if (!json_object_is_type(root, json_type_object)) {
		fprintf(stderr, "Configuration error: JSON root object is not hash\n");
		return -EINVAL;
	}

	if ((ret = analyze_ports(root, config)) < 0) {
		return ret;
	}

	if ((ret = analyze_eal_args(root, config)) < 0) {
		return ret;
	}

	return 0;
} /* analyze_root */

/** Parses the given JSON configuration file for the IPv4 addresses to assign
 * to each interface.  An example configuration file looks like:
 *
 * { "ports": [{ "ipv4_address": "10.0.0.1/24" },
 *             { "ipv4_address": "10.1.0.1/24" }]}
 *
 * On input, out_size is the size of the out array and the number of detected
 * ports.  On output, it is the number of actually configured ports, which will
 * always be less than or equal to the value given as input.
 */
int
parse_config(FILE *in, struct usiw_config *config)
{
	static const size_t buf_size = 1024;
	char buf[buf_size], buf2[buf_size];
	enum json_tokener_error err;
	struct json_tokener *tok;
	struct json_object *obj;
	ssize_t nbytes, offset;
	int ret;

	offset = 0;
	tok = json_tokener_new();
	while ((nbytes = fread(buf + offset, 1, buf_size, in)) > 0) {
		nbytes += offset;
		obj = json_tokener_parse_ex(tok, buf, nbytes);
		if (obj) {
			break;
		}
		err = json_tokener_get_error(tok);
		if (err != json_tokener_continue) {
			fprintf(stderr, "Configuration parse error: %s\n",
					json_tokener_error_desc(err));
			ret = -EINVAL;
			goto free_tokener;
		}
		if (tok->char_offset > 0) {
			strncpy(buf2, buf + tok->char_offset,
					nbytes - tok->char_offset);
			strncpy(buf, buf2, nbytes - tok->char_offset);
		}
		offset = tok->char_offset;
	}
	if (nbytes == 0) {
		if (feof(in)) {
			fprintf(stderr, "Configuration parse error: reached EOF but did not parse object\n");
			ret = -EINVAL;
		} else {
			fprintf(stderr, "Configuration parse error: error reading configuration file\n");
			ret = -EIO;
		}
		goto free_object;
	}
	if (tok->char_offset < offset + nbytes) {
		fprintf(stderr, "Configuration parse error: extra data after end of JSON object: \"%*s\"\n",
				(int)(offset + nbytes - tok->char_offset),
				buf + tok->char_offset);
		ret = -EINVAL;
		goto free_object;
	}

	ret = analyze_root(obj, config);

free_object:
	json_object_put(obj);
free_tokener:
	json_tokener_free(tok);
	return ret;
} /* parse_config */

void
usiw_config_destroy(struct usiw_config *config)
{
	int i;

	for (i = 0; i < config->eal_argc; i++) {
		free(config->freelist[i]);
	}
	free(config->eal_argv);
	free(config->freelist);
	free(config->port_config);
} /* usiw_config_free */

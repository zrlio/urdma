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
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>

#include "config_file.h"
#include "util.h"

int
urdma__config_file_get_ports(struct usiw_config *config,
			     struct usiw_port_config **port_config)
{
	struct json_object *ports, *port, *ipv4;
	int port_count, i;

	if (!json_object_object_get_ex(config->root, "ports", &ports)) {
		fprintf(stderr, "Configuration error: JSON root object has no \"ports\" field\n");
		return -EINVAL;
	}

	if (!json_object_is_type(ports, json_type_array)) {
		fprintf(stderr, "Configuration error: \"ports\" field is not an array\n");
		return -EINVAL;
	}

	port_count = json_object_array_length(ports);
	*port_config = calloc(port_count, sizeof(**port_config));
	if (!(*port_config)) {
		return -ENOMEM;
	}
	for (i = 0; i < port_count; i++) {
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
		strncpy((*port_config)[i].ipv4_address,
				json_object_get_string(ipv4),
				ipv4_addr_len_max);
	}

	return port_count;
} /* urdma__config_file_get_ports */

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
get_arg_count(struct usiw_config *config, struct json_object **args)
{
	if (!json_object_object_get_ex(config->root, "eal_args", args)) {
		return 0;
	}

	if (!json_object_is_type(*args, json_type_object)) {
		fprintf(stderr, "Configuration error: \"eal_args\" field is not a hash\n");
		return -EINVAL;
	}

	return json_object_object_length(*args) + 1;
} /* get_arg_count */


/** Parse the user-supplied EAL arguments in the configuration file into an
 * argument array. If argv is NULL, return the expected value of argc. The
 * user is expected to allocate argv with at least (argc + 1) elements, in order
 * to hold the terminating argv[argc] = NULL element. The behavior is undefined
 * if argv is not large enough. */
int
urdma__config_file_get_eal_args(struct usiw_config *config, char **argv)
{
	struct json_object *args;
	int argc, key_len, len, i, ret;

	argc = get_arg_count(config, &args);
	if (!argv) {
		return argc;
	}

	argv[0] = get_argv0();
	if (!argv[0]) {
		i = 0;
		goto free_args;
	}

	i = 1;
	json_object_object_foreach(args, key, value) {
		key_len = strlen(key);
		switch (json_object_get_type(value)) {
		case json_type_boolean:
			if (json_object_get_boolean(value)) {
				ret = asprintf(&argv[i++], "-%s%s",
						key_len > 1 ? "-" : "",
						key);
				if (ret < 0) {
					goto free_args;
				}
			}
			break;
		case json_type_string:
			if (key_len > 1) {
				ret = asprintf(&argv[i++], "--%s=%s",
						key,
						json_object_get_string(value));
				if (ret < 0) {
					goto free_args;
				}
			} else {
				ret = asprintf(&argv[i++], "-%s",
						key);
				if (ret < 0) {
					goto free_args;
				}
				ret = asprintf(&argv[i++], "%s",
						json_object_get_string(value));
				if (ret < 0) {
					goto free_args;
				}
			}
			break;
		case json_type_int:
			if (key_len > 1) {
				ret = asprintf(&argv[i++], "--%s=%" PRId64,
						key,
						json_object_get_int64(value));
				if (ret < 0) {
					goto free_args;
				}
			} else {
				ret = asprintf(&argv[i++], "-%s",
						key);
				if (ret < 0) {
					goto free_args;
				}
				ret = asprintf(&argv[i++], "%" PRId64,
						json_object_get_int64(value));
				if (ret < 0) {
					goto free_args;
				}
			}
			break;
		case json_type_double:
			if (key_len > 1) {
				ret = asprintf(&argv[i++], "--%s=%.12f",
						key,
						json_object_get_double(value));
				if (ret < 0) {
					goto free_args;
				}
			} else {
				ret = asprintf(&argv[i++], "-%s",
						key);
				if (ret < 0) {
					goto free_args;
				}
				ret = asprintf(&argv[i++], "%.12f",
						json_object_get_double(value));
				if (ret < 0) {
					goto free_args;
				}
			}
			break;
		default:
			errno = EINVAL;
			goto free_args;
		}
	}
	argv[i] = NULL;

	return i;

free_args:
	for (len = i, i = 0; i < len; ++i) {
		free(argv[i]);
	}
	return -errno;
} /* urdma__config_file_get_eal_args */


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
static int
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
	if (!json_object_is_type(obj, json_type_object)) {
		fprintf(stderr, "Configuration error: JSON root object is not hash\n");
		return -EINVAL;
	}
	config->root = obj;

	ret = 0;
	goto free_tokener;

free_object:
	json_object_put(obj);
free_tokener:
	json_tokener_free(tok);
	return ret;
} /* parse_config */

int
urdma__config_file_open(struct usiw_config *config)
{
	static const char conf_file_name[] = urdma_confdir "/" PACKAGE_NAME ".json";
	FILE *in;
	int fd;
	int ret;

	fd = open(conf_file_name, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		return -errno;
	}
	in = fdopen(fd, "r");
	if (!in) {
		close(fd);
		return -errno;
	}

	ret = parse_config(in, config);
	fclose(in);
	return ret;
} /* urdma__config_file_open */

void
urdma__config_file_close(struct usiw_config *config)
{
	json_object_put(config->root);
} /* usiw_config_free */

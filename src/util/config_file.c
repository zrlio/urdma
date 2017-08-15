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

#define DEFAULT_MTU 1500
#define JUMBO_MTU 9000


static int
get_int_value(struct json_object *parent, int index,
		const char *name, int min, int max, int def, int *val)
{
	struct json_object *obj;

	if (json_object_object_get_ex(parent, name, &obj)) {
		if (!json_object_is_type(obj, json_type_int)
				&& !json_object_is_type(obj,
							json_type_string)) {
			fprintf(stderr,
				"Configuration error: port %d field \"%s\" is not integer\n",
				index, name);
			return -EINVAL;
		}
		*val = json_object_get_int(obj);
		if (*val < min || *val > max) {
			fprintf(stderr, "Configuration error: port %d field \"%s\" (%u) must be in range [%u, %u]\n",
					index, name, *val, min, max);
			return -EINVAL;
		}
	} else {
		*val = def;
	}

	return 0;
} /* get_int_value */


static int
get_uint_value(struct json_object *parent, int index,
		const char *name, unsigned int min, unsigned int max,
		unsigned int def, unsigned int *val)
{
	struct json_object *obj;

	if (json_object_object_get_ex(parent, name, &obj)) {
		if (!json_object_is_type(obj, json_type_int)
				&& !json_object_is_type(obj,
							json_type_string)) {
			fprintf(stderr,
				"Configuration error: port %d field \"%s\" is not integer\n",
				index, name);
			return -EINVAL;
		}
		*val = json_object_get_int(obj);
		if (*val < min || *val > max) {
			fprintf(stderr, "Configuration error: port %d field \"%s\" (%u) must be in range [%u, %u]\n",
					index, name, *val, min, max);
			return -EINVAL;
		}
	} else {
		*val = def;
	}

	return 0;
} /* get_uint_value */

/* Parse a PCI address of form [XXXX:]XX:XX.X */
static int
parse_pci_addr(const char *str, struct rte_pci_addr *dev_addr)
{
	static const size_t len_with_domain = 12;
	static const size_t len_without_domain = 7;
	size_t len;

	len = strlen(str);
	if (len == len_with_domain) {
		return eal_parse_pci_DomBDF(str, dev_addr);
	} else if (len == len_without_domain) {
		return eal_parse_pci_BDF(str, dev_addr);
	} else {
		return -EINVAL;
	}
} /* parse_pci_addr */

int
urdma__config_file_get_ports(struct usiw_config *config,
			     struct usiw_port_config **port_config)
{
	struct json_object *ports, *port, *obj;
	int port_count, i, ret;
	bool can_use_index = true;

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
		if (json_object_object_get_ex(port, "pci_address", &obj)) {
			(*port_config)[i].id_type = urdma_port_id_pci;
			can_use_index = false;

			if (!json_object_is_type(obj, json_type_string)) {
				fprintf(stderr, "Configuration error: pci_address is not string\n");
				return -EINVAL;
			}

			if ((ret = parse_pci_addr(json_object_get_string(obj),
					&(*port_config)[i].pci_address)) != 0) {
				fprintf(stderr, "Configuration error: pci_address must be of form [XXXX:]XX:XX.X\n");
				return -EINVAL;
			}
		} else if (can_use_index) {
			(*port_config)[i].id_type = urdma_port_id_index;
		} else {
			fprintf(stderr, "Configuration error: must specify pci_address for ALL ports\n");
			return -EINVAL;
		}
		if (!json_object_object_get_ex(port, "ipv4_address", &obj)) {
			fprintf(stderr, "Configuration error: port has no \"ipv4_address\" field\n");
			return -EINVAL;
		}
		if (!json_object_is_type(obj, json_type_string)) {
			fprintf(stderr, "Configuration error: ipv4_address is not string\n");
			return -EINVAL;
		}
		strncpy((*port_config)[i].ipv4_address,
				json_object_get_string(obj),
				ipv4_addr_len_max);

		if (json_object_object_get_ex(port, "mtu", &obj)) {
			if (!json_object_is_type(obj, json_type_int)
					&& !json_object_is_type(obj,
						json_type_string)) {
				fprintf(stderr, "Configuration error: port %d mtu is not integer\n", i);
				return -EINVAL;
			}
			(*port_config)[i].mtu = json_object_get_int(obj);
			if ((*port_config)[i].mtu != DEFAULT_MTU
					&& (*port_config)[i].mtu != JUMBO_MTU) {
				fprintf(stderr, "Configuration error: port %d mtu %u invalid; expected 1500 or 9000\n",
						i, (*port_config)[i].mtu);
				return -EINVAL;
			}
		} else {
			(*port_config)[i].mtu = DEFAULT_MTU;
		}

		if (get_int_value(port, i, "max_qp", 1, UINT16_MAX, -1,
				&(*port_config)[i].max_qp) < 0) {
			return -EINVAL;
		}
		if (get_uint_value(port, i, "rx_desc_count",
					1, UINT_MAX, UINT_MAX,
					&(*port_config)[i].rx_desc_count) < 0) {
			return -EINVAL;
		}
		if (get_uint_value(port, i, "rx_burst_size",
					1, (*port_config)[i].rx_desc_count,
					((*port_config)[i].rx_desc_count > 32)
					? (*port_config)[i].rx_desc_count : 32,
					&(*port_config)[i].rx_burst_size) < 0) {
			return -EINVAL;
		}
		if (get_uint_value(port, i, "tx_desc_count",
					1, UINT_MAX, UINT_MAX,
					&(*port_config)[i].tx_desc_count) < 0) {
			return -EINVAL;
		}
		if (get_uint_value(port, i, "tx_burst_size",
					1, (*port_config)[i].tx_desc_count, 8,
					&(*port_config)[i].tx_burst_size) < 0) {
			return -EINVAL;
		}
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


static char *
get_default_sock_name(void)
{
	static const char *default_sock_name = "/urdma/urdma.sock";
	char *sock_path;
	char *runtime_dir;
	size_t len;

	runtime_dir = getenv("XDG_RUNTIME_DIR");
	if (!runtime_dir || !(*runtime_dir)) {
		return NULL;
	}

	len = strlen(runtime_dir);
	sock_path = malloc(len + strlen(default_sock_name) + 1);
	if (!sock_path) {
		return NULL;
	}

	strncpy(sock_path, runtime_dir, len + 1);
	return strcat(sock_path, default_sock_name);
} /* get_default_sock_name */


char *
urdma__config_file_get_sock_name(struct usiw_config *config)
{
	struct json_object *sock_name;

	if (!json_object_object_get_ex(config->root, "socket", &sock_name)) {
		return get_default_sock_name();
	}

	if (!json_object_is_type(sock_name, json_type_string)) {
		fprintf(stderr, "Configuration error: \"socket\" field not a string\n");
		return NULL;
	}

	return strdup(json_object_get_string(sock_name));
} /* urdma__config_file_get_sock_name */

int
urdma__config_file_get_timer_interval(struct usiw_config *config)
{
	struct json_object *interval;

	if (!json_object_object_get_ex(config->root, "stats_timer_interval",
								&interval)) {
		return 0;
	}

	if (!json_object_is_type(interval, json_type_int)) {
		fprintf(stderr, "Configuration error: \"stats_timer_interval\" field not an integer\n");
		return 0;
	}

	return json_object_get_int(interval);
} /* urdma__config_file_get_timer_interval */


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

#!/usr/bin/env python3
#
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

import random

key_count = 10000
op_count = 250000
value_size_min = 128
value_size_max = 20480

char_range = range(ord('a'), ord('z'))

def random_string(size_range, char_range):
    size = random.choice(size_range)
    key = ""
    for x in range(size):
        key += chr(random.choice(char_range))
    return key

def make_set_request(key):
    value = random_string(range(value_size_min, value_size_max), char_range)
    print("set", key, 0, 0, len(value), end='\r\n')
    print(value, end='\r\n')

def make_get_request(key):
    print("get", key, end='\r\n')

def main():
    random.seed()
    key_list = []
    for x in range(key_count):
        key = random_string(range(5, 20), char_range)
        key_list.append(key)

    # Seed phase
    for key in key_list:
        value = random_string(range(value_size_min, value_size_max), char_range)
        print("add", key, 0, 0, len(value), end='\r\n')
        print(value, end='\r\n')

    # Request phase
    for x in range(op_count):
        fn = random.choice([make_set_request, make_get_request])
        key = random.choice(key_list)
        fn(key)

if __name__ == "__main__":
    main()

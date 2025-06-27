/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __NAT_MAPS_H
#define __NAT_MAPS_H

/*
 * This file contains definition of all maps which has been used by balancer
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "nat_consts.h"
#include "nat_structs.h"

// nat binding tables
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct flow_key));
    __uint(value_size, sizeof(struct binding_definition));
    __uint(max_entries, DEFAULT_MAX_ENTRIES_NAT_TABLE);
    __uint(map_flags, NO_FLAGS);
} nat_binding_table SEC(".maps");
// BPF_ANNOTATE_KV_PAIR(nat_binding_table, struct flow_key, struct binding_definition);

// map which contains 1 elemnent with the last idx for the free_port array
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
    __uint(map_flags, NO_FLAGS);
} last_free_port_idx SEC(".maps");
// BPF_ANNOTATE_KV_PAIR(last_free_port_idx, __u32, __u32);

// map which contains the free_port list
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u16));
    __uint(max_entries, MAX_FREE_PORTS_ENTRIES);
    __uint(map_flags, NO_FLAGS);
} free_ports SEC(".maps");
// BPF_ANNOTATE_KV_PAIR(free_ports, __u32, __u16);

#endif // of _NAT_MAPS

// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_SIIT_TYPES_H_
#define _NET_SIIT_TYPES_H_

/*
 * @file
 * Kernel-specific core data types and routines.
 */

#include <linux/netfilter.h>
#include <linux/kernel.h>

#define PLATEAUS_MAX 64

struct mtu_plateaus {
	__u16 values[PLATEAUS_MAX];
	/* Actual length of the values array. */
	__u16 count;
};

/*
 * The network component of a IPv6 address.
 */
struct ipv6_prefix {
	/* IPv6 prefix. The suffix is most of the time assumed to be zero. */
	struct in6_addr addr;
	/* Number of bits from "address" which represent the network. */
	__u8 len;
};

/*
 * A copy of the entire running configuration, excluding databases.
 */
struct ipxl_cfg {
	struct ipv6_prefix pool6;

	struct in6_addr pool6791v6;
	struct in_addr pool6791v4;
	struct in6_addr icmp6err_saddr;

	/*
	 * Smallest reachable IPv6 MTU.
	 *
	 * Because DF does not exist in IPv6, Jool must ensure that that any
	 * DF-disabled IPv4 packet translates into fragments sized this or less.
	 * Otherwise these packets might be black-holed.
	 */
	__u32 lowest_ipv6_mtu;

	/*
	 * If the translator detects the source of the incoming packet does not
	 * implement RFC 1191, these are the plateau values used to determine a
	 * likely path MTU for outgoing ICMPv6 fragmentation needed packets.
	 * The translator is supposed to pick the greatest plateau value that is
	 * less than the incoming packet's Total Length field.
	 */
	struct mtu_plateaus plateaus;

	/*
	 * Amend the UDP checksum of incoming IPv4-UDP packets
	 * when it's zero? Otherwise these packets will be
	 * dropped (because they're illegal in IPv6).
	 */
	bool compute_udp_csum_zero;
};

#endif /* _NET_SIIT_TYPES_H_ */

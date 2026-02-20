/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_CFG_H_
#define _NET_IPXLAT_CFG_H_

#include <linux/in.h>
#include <linux/in6.h>

#define PLATEAUS_MAX 64

struct mtu_plateaus {
	u16 values[PLATEAUS_MAX];
	u16 count;
};

struct ipv6_prefix {
	struct in6_addr addr;
	u8 len;
};

struct ipxl_cfg {
	struct ipv6_prefix pool6;
	struct in6_addr pool6791v6;
	struct in_addr pool6791v4;
	u32 lowest_ipv6_mtu;
	struct mtu_plateaus plateaus;
	bool compute_udp_csum_zero;
};

#endif /* _NET_IPXLAT_CFG_H_ */

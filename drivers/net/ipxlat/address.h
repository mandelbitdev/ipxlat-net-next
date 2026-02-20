/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_ADDRESS_H_
#define _NET_IPXLAT_ADDRESS_H_

#include <linux/ip.h>
#include <net/ipv6.h>

#include "cfg.h"

void ipxl_addr_46(const struct ipv6_prefix *pool6, __be32 addr4,
		  struct in6_addr *addr6);

int ipxl_addrs_64(const struct ipxl_cfg *cfg, const struct ipv6hdr *hdr6,
		  bool icmp_err, __be32 *src, __be32 *dst);

static inline void ipxl_addrs_46(const struct ipxl_cfg *cfg,
				 const struct iphdr *iph4, struct ipv6hdr *iph6)
{
	ipxl_addr_46(&cfg->pool6, iph4->saddr, &iph6->saddr);
	ipxl_addr_46(&cfg->pool6, iph4->daddr, &iph6->daddr);
}

#endif /* _NET_IPXLAT_ADDRESS_H_ */

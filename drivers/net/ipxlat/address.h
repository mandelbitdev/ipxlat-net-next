// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef SRC_MOD_NAT64_COMPUTE_OUTGOING_TUPLE_H_
#define SRC_MOD_NAT64_COMPUTE_OUTGOING_TUPLE_H_

/*
 * @file
 * Third step in the packet processing algorithm defined in the RFC.
 * The 3.6 section of RFC 6146 is encapsulated in this module.
 * Infers a tuple (summary) of the outgoing packet, yet to be created.
 */

#include "translation_state.h"

void siit46_addr(const struct ipv6_prefix *pool6, __be32 addr4,
		 struct in6_addr *addr6);

int siit64_addrs(const struct ipxl_cfg *cfg, const struct ipv6hdr *hdr6,
		 bool icmp_err, __be32 *src, __be32 *dst);
int siit64_addrs_skb(const struct ipxl_cfg *cfg, struct sk_buff *skb,
		     bool icmp_err, __be32 *src, __be32 *dst);
static inline void siit46_addrs_skb(const struct ipxl_cfg *cfg,
				    const struct iphdr *iph4,
				    struct ipv6hdr *iph6)
{
	siit46_addr(&cfg->pool6, iph4->saddr, &iph6->saddr);
	siit46_addr(&cfg->pool6, iph4->daddr, &iph6->daddr);
}

#endif /* SRC_MOD_NAT64_COMPUTE_OUTGOING_TUPLE_H_ */

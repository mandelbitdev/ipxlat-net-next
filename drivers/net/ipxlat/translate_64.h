/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_TRANSLATE_64_H_
#define _NET_IPXLAT_TRANSLATE_64_H_

#include "ipxlpriv.h"

struct sk_buff;
struct iphdr;
struct ipv6hdr;

void ipxl_64_build_l3(struct iphdr *iph4, const struct ipv6hdr *iph6,
		      unsigned int tot_len, __be16 frag_off, u8 protocol,
		      __be32 saddr, __be32 daddr, u8 ttl, __be16 id);

int ipxl_64_translate(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb);

#endif /* _NET_IPXLAT_TRANSLATE_64_H_ */

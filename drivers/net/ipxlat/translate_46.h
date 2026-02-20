/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_TRANSLATE_46_H_
#define _NET_IPXLAT_TRANSLATE_46_H_

#include "ipxlpriv.h"

struct iphdr;
struct ipv6hdr;
struct frag_hdr;
struct sk_buff;

u8 ipxl_proto_to_nexthdr(u8 protocol);
void ipxl_46_frag_hdr_build(struct frag_hdr *fh6, const struct iphdr *hdr4,
			    u8 l4_proto);
void ipxl_46_build_l3(struct ipv6hdr *iph6, const struct iphdr *iph4,
		      unsigned int payload_len, u8 nexthdr, u8 hop_limit);
int ipxl_46_prefrag_plan(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb);
int ipxl_46_translate(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb);

#endif /* _NET_IPXLAT_TRANSLATE_46_H_ */

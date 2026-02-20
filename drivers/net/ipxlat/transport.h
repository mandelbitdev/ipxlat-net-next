/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_TRANSPORT_H_
#define _NET_IPXLAT_TRANSPORT_H_

#include "packet.h"

struct in6_addr;

int ipxl_set_partial_csum(struct sk_buff *skb, u16 csum_offset);
unsigned int ipxl_l4_min_len(u8 protocol);
int ipxl_cb_rebase_offsets(struct ipxl_cb *cb, int delta);
bool ipxl_cb_offsets_valid(const struct ipxl_cb *cb);
__sum16 ipxl_l4_csum_ipv6(const struct in6_addr *saddr,
			  const struct in6_addr *daddr,
			  const struct sk_buff *skb,
			  unsigned int l4_off, unsigned int l4_len, u8 proto);
__sum16 ipxl_icmp6_csum(const struct ipv6hdr *iph6,
			const struct sk_buff *skb);
int ipxl_46_offload_finalize(struct sk_buff *skb, u8 l4_proto,
			     bool is_fragment);
int ipxl_64_offload_finalize(struct sk_buff *skb, u8 l4_proto,
			     bool is_fragment);
int ipxl_64_tcp(struct sk_buff *skb, const struct ipv6hdr *in6, bool inner);
int ipxl_64_udp(struct sk_buff *skb, const struct ipv6hdr *in6, bool inner);
int ipxl_64_inner_tcp(struct sk_buff *skb, const struct ipv6hdr *in6,
		      const struct iphdr *out4, struct tcphdr *tcp_new);
int ipxl_64_inner_udp(struct sk_buff *skb, const struct ipv6hdr *in6,
		      const struct iphdr *out4, struct udphdr *udp_new);
int ipxl_46_tcp(struct sk_buff *skb, const struct iphdr *in4,
		const struct ipv6hdr *iph6, struct tcphdr *tcp_new, bool inner);
int ipxl_46_udp(struct sk_buff *skb, const struct iphdr *in4,
		const struct ipv6hdr *iph6, struct udphdr *udp_new,
		unsigned int l4_off, unsigned int zero_csum_len, bool inner);
int ipxl_icmp_relayout(struct sk_buff *skb, unsigned int outer_len,
		       unsigned int in_ipl, unsigned int in_iel,
		       unsigned int out_ipl, unsigned int out_pad,
		       unsigned int out_iel);

#endif /* _NET_IPXLAT_TRANSPORT_H_ */

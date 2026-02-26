/* SPDX-License-Identifier: GPL-2.0 */
/*  IPXLAT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2026- Mandelbit, SRL
 *
 *  Author:	Alberto Leiva Popper <ydahhrk@gmail.com>
 *		Antonio Quartulli <antonio@mandelbit.com>
 *		Ralf Lici <ralf@mandelbit.com>
 */

#ifndef _NET_IPXLAT_TRANSPORT_H_
#define _NET_IPXLAT_TRANSPORT_H_

#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

/**
 * ipxl_l4_min_len - minimum transport header size for protocol
 * @protocol: transport protocol identifier
 *
 * Return: minimum header length for @protocol, or 0 if unsupported.
 */
static inline unsigned int ipxl_l4_min_len(u8 protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return sizeof(struct tcphdr);
	case IPPROTO_UDP:
		return sizeof(struct udphdr);
	case IPPROTO_ICMP:
		return sizeof(struct icmphdr);
	default:
		return 0;
	}
}

/**
 * ipxl_set_partial_csum - program CHECKSUM_PARTIAL metadata on skb
 * @skb: packet with transport checksum field
 * @csum_offset: offset of checksum field within transport header
 *
 * Return: 0 on success, negative errno on invalid skb state.
 */
int ipxl_set_partial_csum(struct sk_buff *skb, u16 csum_offset);

/**
 * ipxl_l4_csum_ipv6 - compute full L4 checksum with IPv6 pseudo-header
 * @saddr: IPv6 source address
 * @daddr: IPv6 destination address
 * @skb: packet buffer
 * @l4_off: transport header offset
 * @l4_len: transport span (header + payload)
 * @proto: transport protocol
 *
 * Return: finalized transport checksum for IPv6 packet context.
 */
__sum16 ipxl_l4_csum_ipv6(const struct in6_addr *saddr,
			  const struct in6_addr *daddr,
			  const struct sk_buff *skb, unsigned int l4_off,
			  unsigned int l4_len, u8 proto);

/**
 * ipxl_icmp_relayout - resize quoted ICMP payload/extensions in place
 * @skb: packet buffer
 * @outer_len: offset to quoted datagram start
 * @in_ipl: input datagram payload length
 * @in_iel: input extension length
 * @out_ipl: output datagram payload length
 * @out_pad: output pad bytes between datagram and extensions
 * @out_iel: output extension length
 *
 * This helper may move payload bytes and adjust skb tail length.
 *
 * Return: 0 on success, negative errno on resize/memory failures.
 */
int ipxl_icmp_relayout(struct sk_buff *skb, unsigned int outer_len,
		       unsigned int in_ipl, unsigned int in_iel,
		       unsigned int out_ipl, unsigned int out_pad,
		       unsigned int out_iel);

/**
 * ipxl_finalize_offload - normalize checksum/GSO metadata after translation
 * @skb: translated packet
 * @l4_proto: resulting transport protocol
 * @is_fragment: resulting packet is fragmented
 * @gso_from: input TCP GSO type bit
 * @gso_to: output TCP GSO type bit
 *
 * Converts TCP GSO family bits and clears stale checksum/hash state when
 * offload metadata cannot be preserved across address-family translation.
 *
 * Return: 0 on success, negative errno on unsupported/offload-incompatible
 * input.
 */
int ipxl_finalize_offload(struct sk_buff *skb, u8 l4_proto, bool is_fragment,
			  u32 gso_from, u32 gso_to);

/* outer transport translation helpers (packet L3 already translated) */
int ipxl_46_outer_tcp(struct sk_buff *skb, const struct iphdr *in4);
int ipxl_46_outer_udp(struct sk_buff *skb, const struct iphdr *in4);

/* quoted-inner transport translation helpers for ICMP error payloads */
int ipxl_46_inner_tcp(struct sk_buff *skb, const struct iphdr *in4,
		      const struct ipv6hdr *iph6, struct tcphdr *tcp_new);
int ipxl_46_inner_udp(struct sk_buff *skb, const struct iphdr *in4,
		      const struct ipv6hdr *iph6, struct udphdr *udp_new);

/* outer transport translation helpers (packet L3 already translated) */
int ipxl_64_outer_tcp(struct sk_buff *skb, const struct ipv6hdr *in6);
int ipxl_64_outer_udp(struct sk_buff *skb, const struct ipv6hdr *in6);

/* quoted-inner transport translation helpers for ICMP error payloads */
int ipxl_64_inner_tcp(struct sk_buff *skb, const struct ipv6hdr *in6,
		      const struct iphdr *out4, struct tcphdr *tcp_new);
int ipxl_64_inner_udp(struct sk_buff *skb, const struct ipv6hdr *in6,
		      const struct iphdr *out4, struct udphdr *udp_new);

#endif /* _NET_IPXLAT_TRANSPORT_H_ */

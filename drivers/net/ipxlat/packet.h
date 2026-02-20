/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_PACKET_H_
#define _NET_IPXLAT_PACKET_H_

#include <linux/skbuff.h>
#include <linux/build_bug.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/tcp.h>

struct ipxl_pkt_ctx;

struct ipxl_cb {
	u16 l4_off;
	u16 payload_off;
	u16 fragh_off;
	u16 inner_l3_offset;
	u16 inner_l4_offset;
	u16 inner_fragh_off;
	/* L4 span length (UDP header + payload bytes) to checksum when translating outer IPv4 UDP packets that arrive with checksum 0 */
	u16 udp_zero_csum_len;
	u16 inner_udp_zero_csum_len;
	u16 frag_max_size;
	u8 l4_proto;
	u8 inner_l4_proto;
	u8 l3_hdr_len;
	u8 inner_l3_hdr_len;
	bool in_icmp_err;
	bool emit_icmp_err;
	struct {
		u8 type;
		u8 code;
		u32 info;
	} icmp_err;
};

static inline struct ipxl_cb *ipxl_skb_cb(const struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct ipxl_cb) > sizeof(skb->cb));
	return (struct ipxl_cb *)(skb->cb);
}

static inline unsigned int ipxl_skb_datagram_len(const struct sk_buff *skb)
{
	return skb->len - skb_transport_offset(skb);
}

int ipxl_v4_skb_validate(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb);
int ipxl_v6_skb_validate(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb);

static inline u8 ipxl_get_ipv6_tclass(const struct ipv6hdr *hdr)
{
	return (hdr->priority << 4) | (hdr->flow_lbl[0] >> 4);
}

static inline u16 ipxl_get_frag6_offset(const struct frag_hdr *hdr)
{
	return be16_to_cpu(hdr->frag_off) & 0xFFF8U;
}

static inline u16 ipxl_get_frag4_offset(const struct iphdr *hdr)
{
	return (be16_to_cpu(hdr->frag_off) & IP_OFFSET) << 3;
}

static inline bool ipxl_is_first_frag6(const struct frag_hdr *hdr)
{
	return hdr ? (ipxl_get_frag6_offset(hdr) == 0) : true;
}

static inline __be16 ipxl_build_frag6_offset(u16 frag_offset, bool mf)
{
	return cpu_to_be16((frag_offset & 0xFFF8U) | mf);
}

static inline __be16 ipxl_build_frag4_offset(bool df, bool mf, u16 frag_offset)
{
	return cpu_to_be16((df ? (1U << 14) : 0) | (mf ? (1U << 13) : 0) |
			   (frag_offset >> 3));
}

#endif /* _NET_IPXLAT_PACKET_H_ */

// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include <linux/icmp.h>
#include <net/ip.h>
#include <net/ip6_route.h>

#include "translate_46.h"
#include "address.h"
#include "packet.h"
#include "icmp_46.h"
#include "transport.h"
#include "dispatch.h"

static inline __be32 ipxl_46_frag_id_from_v4(const struct iphdr *hdr4)
{
	return cpu_to_be32(be16_to_cpu(hdr4->id));
}

u8 ipxl_proto_to_nexthdr(u8 protocol)
{
	return (protocol == IPPROTO_ICMP) ? NEXTHDR_ICMP : protocol;
}

void ipxl_46_frag_hdr_build(struct frag_hdr *fh6, const struct iphdr *hdr4,
			    u8 l4_proto)
{
	fh6->nexthdr = ipxl_proto_to_nexthdr(l4_proto);
	fh6->reserved = 0;
	fh6->frag_off = ipxl_build_frag6_offset(ipxl_get_frag4_offset(hdr4),
						!!(be16_to_cpu(hdr4->frag_off) &
						   IP_MF));
	fh6->identification = ipxl_46_frag_id_from_v4(hdr4);
}

void ipxl_46_build_l3(struct ipv6hdr *iph6, const struct iphdr *iph4,
		      unsigned int payload_len, u8 nexthdr, u8 hop_limit)
{
	iph6->version = 6;
	iph6->priority = iph4->tos >> 4;
	iph6->flow_lbl[0] = (iph4->tos & 0x0F) << 4;
	iph6->flow_lbl[1] = 0;
	iph6->flow_lbl[2] = 0;
	iph6->payload_len = htons(payload_len);
	iph6->nexthdr = nexthdr;
	iph6->hop_limit = hop_limit;
}

static unsigned int ipxl_46_pmtu(const struct ipxl_pkt_ctx *ctx,
				 const struct sk_buff *skb,
				 const struct iphdr *in4)
{
	struct flowi6 fl6 = {};
	struct dst_entry *dst;
	unsigned int mtu6;

	ipxl_addr_46(&ctx->cfg->pool6, in4->saddr, &fl6.saddr);
	ipxl_addr_46(&ctx->cfg->pool6, in4->daddr, &fl6.daddr);
	fl6.flowi6_mark = skb->mark;

	dst = ip6_route_output(dev_net(ctx->dev), NULL, &fl6);
	if (unlikely(dst->error)) {
		mtu6 = ctx->dev->mtu;
		goto out;
	}

	/* Route lookup can return a very large MTU (eg, local/loopback style
	 * routes) that does not reflect the translator egress constraint.
	 * Clamp with the translator device MTU so DF decisions are stable and
	 * pre-fragment planning never targets packets larger than what this
	 * interface can hand to the next stages.
	 */
	mtu6 = min_t(unsigned int, dst_mtu(dst), ctx->dev->mtu);

out:
	dst_release(dst);
	return mtu6;
}

int ipxl_46_prefrag_plan(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb)
{
	unsigned int pkt_len6, pmtu6, threshold6, frag_max_size;
	unsigned int pkt_len4, old_l3_len, new_l3_len;
	const struct iphdr *in4 = ip_hdr(skb);
	struct ipxl_cb *cb = ipxl_skb_cb(skb);
	int l3_delta, frag_l3_delta;


	if (unlikely(cb->frag_max_size)) {
		DEBUG_NET_WARN_ON_ONCE(1);
		cb->frag_max_size = 0;
	}

	pkt_len4 = iph_totlen(skb, in4);

	old_l3_len = cb->l3_hdr_len;
	new_l3_len = sizeof(struct ipv6hdr) +
		     (ip_is_fragment(in4) ? sizeof(struct frag_hdr) : 0);
	l3_delta = (int)new_l3_len - (int)old_l3_len;

	pkt_len6 = pkt_len4 + l3_delta;
	pmtu6 = ipxl_46_pmtu(ctx, skb, in4);
	threshold6 = min(pmtu6, ctx->cfg->lowest_ipv6_mtu);

	/* DF packets are never locally pre-fragmented */
	if (likely(be16_to_cpu(in4->frag_off) & IP_DF)) {
		/* If we're not allowed to fragment but translation would
		 * exceed the next-hop MTU on the IPv6 side, emit ICMPv4
		 * FRAG_NEEDED.
		 * Incoming ICMPv4 errors are exempt: they proceed to the
		 * ICMP error squeeze/trim path.
		 */
		if (unlikely(pkt_len6 > pmtu6 && !cb->in_icmp_err)) {
			ipxl_mark_icmp_drop(skb, ICMP_DEST_UNREACH,
					    ICMP_FRAG_NEEDED,
					    pmtu6 > 20 ? pmtu6 - 20 : 0);
			return -EINVAL;
		}
		return 0;
	}

	/* DF not set */

	if (likely(pkt_len6 <= threshold6))
		return 0;

	frag_l3_delta =
		(int)(sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)) -
		(int)old_l3_len;
	frag_max_size = threshold6 - frag_l3_delta;
	/* store per-skb prefrag cap: ipxl_46_do_fragment will copy it into
	 * IPCB(skb)->frag_max_size before calling ip_do_fragment
	 */
	cb->frag_max_size = min_t(unsigned int, frag_max_size, IP_MAX_MTU);
	return 0;
}

int ipxl_46_translate(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb)
{
	unsigned int min_l4_len, ip4_len, ip6_len;
	struct ipxl_cb *cb = ipxl_skb_cb(skb);
	const struct iphdr in4 = *ip_hdr(skb);
	const u8 l4_proto = cb->l4_proto;
	bool need_frag, first_frag;
	struct frag_hdr *fh6;
	struct ipv6hdr *iph6;
	int delta, err;


	/* snapshot the original IPv4 header fields before skb layout changes */
	need_frag = ip_is_fragment(&in4);
	first_frag = !(in4.frag_off & htons(IP_OFFSET));
	ip4_len = in4.ihl << 2;
	ip6_len = sizeof(struct ipv6hdr) +
		  (need_frag ? sizeof(struct frag_hdr) : 0);
	delta = (int)ip6_len - (int)ip4_len;

	/* make room for the new hdrs */
	if (unlikely(skb_cow_head(skb, max_t(int, 0, delta))))
		return -ENOMEM;

	/* replace outer L3 area: drop IPv4 hdr, reserve IPv6(+Frag) hdr */
	skb_pull(skb, ip4_len);
	skb_push(skb, ip6_len);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, ip6_len);
	skb->protocol = htons(ETH_P_IPV6);

	/* build outer IPv6 base hdr from translated IPv4 fields */
	iph6 = ipv6_hdr(skb);
	ipxl_46_build_l3(iph6, &in4, skb->len - sizeof(*iph6),
			 ipxl_proto_to_nexthdr(l4_proto), in4.ttl - 1);

	/* translate IPv4 endpoints into IPv6 addresses using pool6 prefix */
	ipxl_addrs_46(ctx->cfg, &in4, iph6);

	/* add IPv6 fragment hdr when the IPv4 packet carried fragmentation */
	if (unlikely(need_frag)) {
		iph6->nexthdr = NEXTHDR_FRAGMENT;

		fh6 = (struct frag_hdr *)(iph6 + 1);
		ipxl_46_frag_hdr_build(fh6, &in4, l4_proto);
		cb->fragh_off = sizeof(struct ipv6hdr);
	}

	/* Rebase cached offsets after L3 size delta.
	 * For outer 4->6 translation this should not underflow: cached offsets
	 * were built from l3_off + ip4_len(+...) and delta = ip6_len - ip4_len,
	 * so ip4_len cancels out after rebasing. A failure here means internal
	 * metadata inconsistency, not a packet validation outcome.
	 */
	err = ipxl_cb_rebase_offsets(cb, delta);
	if (unlikely(err)) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return err;
	}

	cb->l3_hdr_len = ip6_len;
	cb->l4_proto = ipxl_proto_to_nexthdr(l4_proto);
	if (unlikely(!ipxl_cb_offsets_valid(cb))) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return -EINVAL;
	}

	/* non-first fragments have no transport header to translate */
	if (unlikely(!first_frag))
		goto out;

	/* ensure transport bytes are writable before L4 csum/proto rewrites */
	min_l4_len = ipxl_l4_min_len(l4_proto);
	if (unlikely(skb_ensure_writable(skb, skb_transport_offset(skb) +
						      min_l4_len)))
		return -ENOMEM;

	/* translate transport hdr and pseudohdr dependent checksums */
	switch (l4_proto) {
	case IPPROTO_TCP:
		err = ipxl_46_tcp(skb, &in4, iph6, tcp_hdr(skb), false);
		break;
	case IPPROTO_UDP:
		err = ipxl_46_udp(skb, &in4, iph6, udp_hdr(skb),
				  skb_transport_offset(skb),
				  cb->udp_zero_csum_len, false);
		break;
	case IPPROTO_ICMP:
		err = ipxl_46_icmp(ctx, skb);
		break;
	default:
		err = 0;
		break;
	}
	if (unlikely(err))
		return err;

out:
	/* normalize checksum/offload metadata for the translated frame */
	return ipxl_46_offload_finalize(skb, l4_proto, need_frag);
}

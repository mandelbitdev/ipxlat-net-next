// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/ip.h>

#include "icmp_46.h"
#include "address.h"
#include "icmp_compat.h"
#include "translate_46.h"
#include "transport.h"

enum ipxl_icmp_ie_policy {
	IPXL_ICMP_IE_ALLOWED = 0,
	IPXL_ICMP_IE_FORBIDDEN = 1,
};

static int ipxl_46_icmp_squeeze_extensions(struct sk_buff *skb,
					   unsigned int icmp4_ipl,
					   int inner_delta,
					   enum ipxl_icmp_ie_policy ie_policy)
{
	unsigned int icmp6_iel_in, icmp6_iel_out, max_iel, outer_hdrs_len,
		out_pad, payload_len, icmp6_ipl_out_bytes, pkt_len_cap,
		icmp6_ipl_out = 0;
	int icmp6_ipl_in_bytes, err;
	struct ipv6hdr *iph6;
	struct icmp6hdr *ic6;

	/* icmp4_ipl tells where quoted packet ends and extension area starts
	 * in the original ICMPv4 packet
	 */
	if (likely(!icmp4_ipl))
		goto no_extensions;

	/* Compute the boundaries of the ICMPv6 error payload.
	 * The ICMP payload is comprised of both ipl and iel:
	 * - ipl covers the quoted original datagram portion inside the ICMP
	 *   payload,
	 * - iel covers the extension area inside the ICMP payload.
	 */

	/* outer IPv6 hdr len + ICMPv6 hdr len */
	outer_hdrs_len = skb_transport_offset(skb) + sizeof(struct icmp6hdr);
	/* inner packet len (+ extension area len) */
	payload_len = skb->len - outer_hdrs_len;
	/* offset within the translated payload where extension area starts */
	icmp6_ipl_in_bytes = icmp4_ipl + inner_delta;
	if (unlikely(icmp6_ipl_in_bytes < 0 ||
		     icmp6_ipl_in_bytes > payload_len))
		return -EINVAL;

	/* no trailing extension area after the quoted datagram */
	if (icmp6_ipl_in_bytes == payload_len)
		goto no_extensions;

	/* on-wire iel value */
	icmp6_iel_in = payload_len - icmp6_ipl_in_bytes;
	/* maximum extension bytes that can fit in our budget */
	max_iel = IPV6_MIN_MTU - (outer_hdrs_len + ICMP_EXT_ORIG_DGRAM_MIN_LEN);

	if (unlikely(ie_policy == IPXL_ICMP_IE_FORBIDDEN ||
		     icmp6_iel_in > max_iel)) {
		/* (outer headers + quoted datagram) capped at 1280 */
		pkt_len_cap = min_t(unsigned int, skb->len - icmp6_iel_in,
				    IPV6_MIN_MTU);
		/* maximum allowed quoted datagram len */
		icmp6_ipl_out_bytes = pkt_len_cap - outer_hdrs_len;
		out_pad = 0;
		icmp6_iel_out = 0;
		/* set the on-wire RFC4884 ICMPv6 extension delimiter to 0 */
		icmp6_ipl_out = 0;
	} else {
		/* (outer headers + quoted datagram + extensions) capped at 1280 */
		pkt_len_cap = min_t(unsigned int, skb->len, IPV6_MIN_MTU);
		/* maximum allowed quoted datagram len */
		icmp6_ipl_out_bytes =
			round_down(pkt_len_cap - icmp6_iel_in - outer_hdrs_len,
				   sizeof(u64));
		/* 0s to add after the quoted packet but before extensions */
		out_pad = max_t(unsigned int, ICMP_EXT_ORIG_DGRAM_MIN_LEN,
				icmp6_ipl_out_bytes) -
			  icmp6_ipl_out_bytes;
		/* preserve the extension area len */
		icmp6_iel_out = icmp6_iel_in;
		/* on-wire delimiter (quoted + pad) value in 8-byte units */
		icmp6_ipl_out = (icmp6_ipl_out_bytes + out_pad) >> 3;
	}

	/* TODO: FORBIDDEN/no-extension paths only need header writes and
	 * possible trim; avoid requiring full-length writable skb there.
	 */
	err = skb_ensure_writable(skb, skb->len);
	if (unlikely(err))
		return err;

	err = ipxl_icmp_relayout(skb, outer_hdrs_len,
				 (unsigned int)icmp6_ipl_in_bytes, icmp6_iel_in,
				 icmp6_ipl_out_bytes, out_pad, icmp6_iel_out);
	if (unlikely(err))
		return err;

	iph6 = ipv6_hdr(skb);
	iph6->payload_len = htons(skb->len - sizeof(*iph6));

no_extensions:
	if (unlikely(skb->len > IPV6_MIN_MTU)) {
		err = pskb_trim(skb, IPV6_MIN_MTU);
		if (unlikely(err))
			return err;

		iph6 = ipv6_hdr(skb);
		iph6->payload_len = htons(skb->len - sizeof(*iph6));
	}

	ic6 = icmp6_hdr(skb);
	ic6->icmp6_datagram_len = icmp6_ipl_out;
	return 0;
}

static __be32 ipxl_46_icmp_min_mtu6(const struct ipxl_pkt_ctx *ctx,
				    unsigned int pkt_mtu,
				    unsigned int nexthop6mtu,
				    unsigned int nexthop4mtu, u16 tot_len_field)
{
	const u16 *plateaus;
	u32 result;
	u16 count;
	int i;

	if (pkt_mtu == 0) {
		plateaus = ctx->cfg->plateaus.values;
		count = ctx->cfg->plateaus.count;

		for (i = 0; i < count; i++) {
			if (plateaus[i] < tot_len_field) {
				pkt_mtu = plateaus[i];
				break;
			}
		}
	}

	/*
	 * RFC7915 Section 4.2 (ICMPv4 Frag Needed -> ICMPv6 Packet Too Big):
	 *
	 *   max(1280, min(pkt_mtu + 20, mtu6_nexthop, mtu4_nexthop + 20))
	 *
	 * Why each term exists in practice:
	 * - pkt_mtu + 20:
	 *   MTU reported by the IPv4 ICMP error sender, converted to IPv6
	 *   context (+20 for IPv6-vs-IPv4 base header size).
	 * - mtu6_nexthop:
	 *   Current translator knowledge of the IPv6-side next-hop/path MTU.
	 *   Avoid advertising an MTU that is already too large on the v6 side.
	 * - mtu4_nexthop + 20:
	 *   Translator-local IPv4-side next-hop constraint, converted to IPv6
	 *   context. Keeps the advertised value compatible with the IPv4 side.
	 *
	 * The min() picks the tightest known bottleneck.
	 * The max(1280, ...) enforces the IPv6 minimum MTU mandated by RFC7915.
	 */
	result = min(pkt_mtu + 20, min(nexthop6mtu, nexthop4mtu + 20));
	if (result < IPV6_MIN_MTU)
		result = IPV6_MIN_MTU;

	return cpu_to_be32(result);
}

static int ipxl_46_icmp_compute_mtu6(const struct ipxl_pkt_ctx *ctx,
				     struct sk_buff *skb,
				     const struct icmphdr *in_icmp,
				     struct icmp6hdr *out_icmp,
				     const struct iphdr *inner4)
{
	unsigned int in_mtu, out_mtu;

	/* MTU of IPv4 nexthop */
	in_mtu = ctx->dev->mtu;
	/* TODO: derive nexthop MTU from a post-translation IPv6 route lookup. */
	/* MTU of IPv6 nexthop */
	out_mtu = ctx->dev->mtu;
	out_icmp->icmp6_mtu =
		/* in_icmp->un.frag.mtu is the MTU value carried by incoming ICMPv4 Frag Needed */
		ipxl_46_icmp_min_mtu6(ctx, be16_to_cpu(in_icmp->un.frag.mtu),
				      out_mtu, in_mtu,
				      be16_to_cpu(inner4->tot_len));
	return 0;
}

static int ipxl_46_icmp_dest_unreach(const struct ipxl_pkt_ctx *ctx,
				     struct sk_buff *skb,
				     const struct icmphdr *in,
				     struct icmp6hdr *out,
				     const struct iphdr *inner4)
{
	switch (in->code) {
	case ICMP_NET_UNREACH:
	case ICMP_HOST_UNREACH:
	case ICMP_SR_FAILED:
	case ICMP_NET_UNKNOWN:
	case ICMP_HOST_UNKNOWN:
	case ICMP_HOST_ISOLATED:
	case ICMP_NET_UNR_TOS:
	case ICMP_HOST_UNR_TOS:
	case ICMP_PORT_UNREACH:
	case ICMP_NET_ANO:
	case ICMP_HOST_ANO:
	case ICMP_PKT_FILTERED:
	case ICMP_PREC_CUTOFF:
		out->icmp6_unused = 0;
		return 0;
	case ICMP_PROT_UNREACH:
		out->icmp6_pointer =
			cpu_to_be32(offsetof(struct ipv6hdr, nexthdr));
		return 0;
	case ICMP_FRAG_NEEDED:
		return ipxl_46_icmp_compute_mtu6(ctx, skb, in, out, inner4);
	}

	return -EPROTONOSUPPORT;
}

static const u8 ipxl_46_icmp_ptrs[] = { 0,    1, 4,  4,	   0xff, 0xff, 0xff,
					0xff, 7, 6,  0xff, 0xff, 8,    8,
					8,    8, 24, 24,   24,	 24 };

static int ipxl_46_icmp_param_prob(const struct icmphdr *in,
				   struct icmp6hdr *out)
{
	u8 ptr;

	if (unlikely(in->code != ICMP_PTR_INDICATES_ERR &&
		     in->code != ICMP_BAD_LENGTH))
		return -EPROTONOSUPPORT;

	ptr = be32_to_cpu(in->icmp4_unused) >> 24;
	if (unlikely(ptr >= ARRAY_SIZE(ipxl_46_icmp_ptrs) ||
		     ipxl_46_icmp_ptrs[ptr] == 0xff))
		return -EPROTONOSUPPORT;

	out->icmp6_pointer = cpu_to_be32(ipxl_46_icmp_ptrs[ptr]);
	return 0;
}

static int ipxl_46_icmp_info_type_code(const struct icmphdr *in,
				       struct icmp6hdr *out)
{
	switch (in->type) {
	case ICMP_ECHO:
		out->icmp6_type = ICMPV6_ECHO_REQUEST;
		out->icmp6_code = 0;
		out->icmp6_identifier = in->un.echo.id;
		out->icmp6_sequence = in->un.echo.sequence;
		return 0;
	case ICMP_ECHOREPLY:
		out->icmp6_type = ICMPV6_ECHO_REPLY;
		out->icmp6_code = 0;
		out->icmp6_identifier = in->un.echo.id;
		out->icmp6_sequence = in->un.echo.sequence;
		return 0;
	}

	return -EPROTONOSUPPORT;
}

static int ipxl_46_icmp_info(struct sk_buff *skb, const struct icmphdr *icmp4,
			     const struct ipv6hdr *ip6, struct icmp6hdr *icmp6,
			     unsigned int l4_off, bool inner)
{
	struct icmp6hdr icmp6_zero;
	struct icmphdr icmp4_zero;
	__wsum csum;
	int err;

	err = ipxl_46_icmp_info_type_code(icmp4, icmp6);
	if (unlikely(err))
		return -EINVAL;

	if (!inner && skb->ip_summed == CHECKSUM_PARTIAL) {
		icmp6->icmp6_cksum = ~csum_ipv6_magic(&ip6->saddr, &ip6->daddr,
						      skb->len - l4_off,
						      IPPROTO_ICMPV6, 0);
		return ipxl_set_partial_csum(skb, offsetof(struct icmp6hdr,
							   icmp6_cksum));
	}

	icmp4_zero = *icmp4;
	icmp4_zero.checksum = 0;
	icmp6_zero = *icmp6;
	icmp6_zero.icmp6_cksum = 0;
	csum = ~csum_unfold(icmp4->checksum);
	csum = csum_sub(csum, csum_partial(&icmp4_zero, sizeof(icmp4_zero), 0));
	csum = csum_add(csum, csum_partial(&icmp6_zero, sizeof(icmp6_zero), 0));
	icmp6->icmp6_cksum = csum_ipv6_magic(&ip6->saddr, &ip6->daddr,
					     skb->len - l4_off, IPPROTO_ICMPV6,
					     csum);

	/* on the outer header don't interpret csum metadata
	 * as offload/accumulator state anymore
	 */
	if (!inner)
		skb->ip_summed = CHECKSUM_NONE;

	return 0;
}

static int ipxl_46_icmp_type_code(const struct ipxl_pkt_ctx *ctx,
				  struct sk_buff *skb, const struct icmphdr *in,
				  struct icmp6hdr *out,
				  const struct iphdr *inner4,
				  enum ipxl_icmp_ie_policy *ie_policy)
{
	int err;

	*ie_policy = IPXL_ICMP_IE_ALLOWED;

	switch (in->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		return ipxl_46_icmp_info_type_code(in, out);
	case ICMP_DEST_UNREACH:
		switch (in->code) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
		case ICMP_SR_FAILED:
		case ICMP_NET_UNKNOWN:
		case ICMP_HOST_UNKNOWN:
		case ICMP_HOST_ISOLATED:
		case ICMP_NET_UNR_TOS:
		case ICMP_HOST_UNR_TOS:
			out->icmp6_type = ICMPV6_DEST_UNREACH;
			out->icmp6_code = ICMPV6_NOROUTE;
			break;
		case ICMP_PROT_UNREACH:
			out->icmp6_type = ICMPV6_PARAMPROB;
			out->icmp6_code = ICMPV6_UNK_NEXTHDR;
			if (ie_policy)
				*ie_policy = IPXL_ICMP_IE_FORBIDDEN;
			break;
		case ICMP_PORT_UNREACH:
			out->icmp6_type = ICMPV6_DEST_UNREACH;
			out->icmp6_code = ICMPV6_PORT_UNREACH;
			break;
		case ICMP_FRAG_NEEDED:
			out->icmp6_type = ICMPV6_PKT_TOOBIG;
			out->icmp6_code = 0;
			if (ie_policy)
				*ie_policy = IPXL_ICMP_IE_FORBIDDEN;
			break;
		case ICMP_NET_ANO:
		case ICMP_HOST_ANO:
		case ICMP_PKT_FILTERED:
		case ICMP_PREC_CUTOFF:
			out->icmp6_type = ICMPV6_DEST_UNREACH;
			out->icmp6_code = ICMPV6_ADM_PROHIBITED;
			break;
		default:
			return -EPROTONOSUPPORT;
		}
		return ipxl_46_icmp_dest_unreach(ctx, skb, in, out, inner4);
	case ICMP_TIME_EXCEEDED:
		out->icmp6_type = ICMPV6_TIME_EXCEED;
		out->icmp6_code = in->code;
		out->icmp6_unused = 0;
		return 0;
	case ICMP_PARAMETERPROB:
		out->icmp6_type = ICMPV6_PARAMPROB;
		if (ie_policy)
			*ie_policy = IPXL_ICMP_IE_FORBIDDEN;
		switch (in->code) {
		case ICMP_PTR_INDICATES_ERR:
		case ICMP_BAD_LENGTH:
			out->icmp6_code = ICMPV6_HDR_FIELD;
			break;
		default:
			return -EPROTONOSUPPORT;
		}
		err = ipxl_46_icmp_param_prob(in, out);
		if (unlikely(err))
			return err;
		return 0;
	}

	return -EPROTONOSUPPORT;
}

static int ipxl_46_icmp_inner_l4(struct sk_buff *skb, unsigned int inner_l4_off,
				 const struct iphdr *inner4,
				 const struct ipv6hdr *inner6)
{
	const struct ipxl_cb *cb = ipxl_skb_cb(skb);
	struct icmp6hdr *icmp6;
	struct icmphdr icmp4;
	struct tcphdr *tcp;
	struct udphdr *udp;

	switch (inner4->protocol) {
	case IPPROTO_TCP:
		tcp = (struct tcphdr *)(skb->data + inner_l4_off);
		return ipxl_46_tcp(skb, inner4, inner6, tcp, true);
	case IPPROTO_UDP:
		udp = (struct udphdr *)(skb->data + inner_l4_off);
		return ipxl_46_udp(skb, inner4, inner6, udp, inner_l4_off,
				   cb->inner_udp_zero_csum_len, true);
	case IPPROTO_ICMP:
		icmp4 = *(struct icmphdr *)(skb->data + inner_l4_off);
		icmp6 = (struct icmp6hdr *)(skb->data + inner_l4_off);
		return ipxl_46_icmp_info(skb, &icmp4, inner6, icmp6,
					 inner_l4_off, true);
	default:
		return 0;
	}
}

static int ipxl_46_icmp_inner(const struct ipxl_pkt_ctx *ctx,
			      struct sk_buff *skb, const struct iphdr *inner4)
{
	unsigned int inner_l4_off, inner_l3_payload, inner_l4_payload;
	const unsigned int outer_l3_len = skb_transport_offset(skb);
	const unsigned int inner_l3_len = inner4->ihl << 2;
	unsigned int old_prefix, new_prefix, inner_tot_len;
	const bool need_frag = ip_is_fragment(inner4);
	struct ipv6hdr outer_ip6_copy, *inner_ip6;
	struct frag_hdr *fh6;
	int delta;

	/* save a copy of the outer IP header because skb_pull_rcsum + skb_push
	 * destroys that header region
	 */
	outer_ip6_copy = *ipv6_hdr(skb);
	/* outer IPv6 hdr + outer ICMPv4 hdr + inner IPv4 hdr */
	old_prefix = outer_l3_len + sizeof(struct icmphdr) + inner_l3_len;
	/* outer IPv6 hdr + outer ICMPv6 hdr + inner IPv6 hdr (+ frag hdr) */
	new_prefix = outer_l3_len + sizeof(struct icmp6hdr) +
		     sizeof(struct ipv6hdr) +
		     (need_frag ? sizeof(struct frag_hdr) : 0);
	delta = (int)new_prefix - (int)old_prefix;

	if (unlikely(skb_cow_head(skb, max_t(int, 0, delta))))
		return -ENOMEM;

	skb_pull(skb, old_prefix);
	skb_push(skb, new_prefix);
	/* Outer 4->6 translation already set network/transport headers, but
	 * inner relayout pulls/pushes again and changes skb->data placement.
	 * Reinitialize outer header offsets so ip{,v6}_hdr/icmp{,6}_hdr and
	 * skb_transport_offset keep pointing to the outer packet.
	 */
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, outer_l3_len);

	*ipv6_hdr(skb) = outer_ip6_copy;
	ipv6_hdr(skb)->payload_len = htons(skb->len - sizeof(struct ipv6hdr));

	inner_ip6 = (struct ipv6hdr *)(skb->data + outer_l3_len +
				       sizeof(struct icmp6hdr));
	/* Use the quoted IPv4 header's total-length, not skb->len:
	 * skb->len also includes ICMP extension bytes at the end, which are
	 * not part of the quoted inner IP datagram length.
	 */
	inner_tot_len = ntohs(inner4->tot_len);
	if (unlikely(inner_tot_len < inner_l3_len))
		return -EINVAL;
	inner_l3_payload = inner_tot_len - inner_l3_len +
			   (need_frag ? sizeof(struct frag_hdr) : 0);
	ipxl_46_build_l3(inner_ip6, inner4, inner_l3_payload,
			 need_frag ? NEXTHDR_FRAGMENT :
				     ipxl_proto_to_nexthdr(inner4->protocol),
			 inner4->ttl);
	ipxl_addrs_46(ctx->cfg, inner4, inner_ip6);

	if (unlikely(need_frag)) {
		fh6 = (struct frag_hdr *)(inner_ip6 + 1);
		ipxl_46_frag_hdr_build(fh6, inner4, inner4->protocol);
	}

	if (unlikely(inner4->frag_off & htons(IP_OFFSET)))
		return 0;

	inner_l4_off = outer_l3_len + sizeof(struct icmp6hdr) +
		       sizeof(struct ipv6hdr) +
		       (need_frag ? sizeof(struct frag_hdr) : 0);
	inner_l4_payload = inner_l4_off + ipxl_l4_min_len(inner4->protocol);
	if (unlikely(skb_ensure_writable(skb, inner_l4_payload)))
		return -ENOMEM;

	return ipxl_46_icmp_inner_l4(skb, inner_l4_off, inner4, inner_ip6);
}

static int ipxl_46_icmp_error(const struct ipxl_pkt_ctx *ctx,
			      struct sk_buff *skb)
{
	const struct ipxl_cb *cb = ipxl_skb_cb(skb);
	const struct icmphdr icmp4 = *icmp_hdr(skb);
	enum ipxl_icmp_ie_policy ie_policy;
	unsigned int inner4_off;
	struct iphdr inner4_ip;
	int inner_delta, err;

	if (unlikely(!(cb->in_icmp_err))) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return -EINVAL;
	}

	inner4_off = cb->inner_l3_offset;
	/* we can't make assumptions on the alignment of the inner header */
	memcpy(&inner4_ip, skb->data + inner4_off, sizeof(inner4_ip));

	/* translate the inner packet headers */
	err = ipxl_46_icmp_inner(ctx, skb, &inner4_ip);
	if (unlikely(err))
		return err;

	err = ipxl_46_icmp_type_code(ctx, skb, &icmp4, icmp6_hdr(skb),
				     &inner4_ip, &ie_policy);
	if (unlikely(err))
		return err;

	inner_delta = sizeof(struct ipv6hdr) +
		      (ip_is_fragment(&inner4_ip) * sizeof(struct frag_hdr)) -
		      (inner4_ip.ihl << 2);
	err = ipxl_46_icmp_squeeze_extensions(skb,
					      icmp4.icmp4_datagram_length << 2,
					      inner_delta, ie_policy);
	if (unlikely(err))
		return err;

	icmp6_hdr(skb)->icmp6_cksum = 0;
	icmp6_hdr(skb)->icmp6_cksum = ipxl_icmp6_csum(ipv6_hdr(skb), skb);
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

int ipxl_46_icmp(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb)
{
	const struct icmphdr icmp4 = *icmp_hdr(skb);

	if (unlikely(ipxl_skb_cb(skb)->in_icmp_err))
		return ipxl_46_icmp_error(ctx, skb);

	return ipxl_46_icmp_info(skb, &icmp4, ipv6_hdr(skb), icmp6_hdr(skb),
				 skb_transport_offset(skb), false);
}

// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/ipv6.h>

#include "icmp_64.h"
#include "address.h"
#include "icmp_compat.h"
#include "translate_64.h"
#include "transport.h"

enum ipxl_icmp_ie_policy {
	IPXL_ICMP_IE_ALLOWED = 0,
	IPXL_ICMP_IE_FORBIDDEN = 1,
};

static void ipxl_64_icmp_compute_csum4(struct sk_buff *skb)
{
	struct icmphdr *hdr = icmp_hdr(skb);

	/*
	 * This function only gets called for ICMP error checksums, so
	 * ipxl_get_skb_datagram_len() is fine.
	 */
	hdr->checksum = 0;
	hdr->checksum = csum_fold(skb_checksum(skb, skb_transport_offset(skb),
					       ipxl_skb_datagram_len(skb), 0));
	skb->ip_summed = CHECKSUM_NONE;
}

static u8 ipxl_64_nexthdr_to_proto(u8 nexthdr)
{
	return (nexthdr == NEXTHDR_ICMP) ? IPPROTO_ICMP : nexthdr;
}

static void update_total_length(struct sk_buff *out)
{
	unsigned int new_len;
	struct iphdr *hdr;

	hdr = ip_hdr(out);
	new_len = out->len;

	if (be16_to_cpu(hdr->tot_len) == new_len)
		return;

	hdr->tot_len = cpu_to_be16(new_len);
	hdr->frag_off &= cpu_to_be16(~IP_DF);
	hdr->check = 0;
	hdr->check = ip_fast_csum(hdr, hdr->ihl);
}

static int ipxl_64_icmp_info_type_code(const struct icmp6hdr *in,
				       struct icmphdr *out)
{
	switch (in->icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		out->type = ICMP_ECHO;
		out->code = 0;
		out->un.echo.id = in->icmp6_identifier;
		out->un.echo.sequence = in->icmp6_sequence;
		return 0;
	case ICMPV6_ECHO_REPLY:
		out->type = ICMP_ECHOREPLY;
		out->code = 0;
		out->un.echo.id = in->icmp6_identifier;
		out->un.echo.sequence = in->icmp6_sequence;
		return 0;
	default:
		return -EINVAL;
	}
}

static __sum16 ipxl_64_icmp_info_csum(const struct ipv6hdr *in6,
				      const struct icmp6hdr *in_icmp6,
				      const struct icmphdr *out_icmp4,
				      unsigned int l4_len)
{
	struct icmp6hdr icmp6_zero;
	struct icmphdr icmp4_zero;
	__wsum csum, tmp;

	icmp6_zero = *in_icmp6;
	icmp6_zero.icmp6_cksum = 0;
	icmp4_zero = *out_icmp4;
	icmp4_zero.checksum = 0;

	csum = ~csum_unfold(in_icmp6->icmp6_cksum);
	tmp = ~csum_unfold(csum_ipv6_magic(&in6->saddr, &in6->daddr, l4_len,
					   NEXTHDR_ICMP, 0));
	csum = csum_sub(csum, tmp);
	csum = csum_sub(csum, csum_partial(&icmp6_zero, sizeof(icmp6_zero), 0));
	csum = csum_add(csum, csum_partial(&icmp4_zero, sizeof(icmp4_zero), 0));

	return csum_fold(csum);
}

static int ipxl_64_icmp_info(struct sk_buff *skb, const struct ipv6hdr *in6)
{
	struct icmp6hdr ic6_copy, *ic6;
	struct icmphdr *ic4;
	int err;

	ic6 = icmp6_hdr(skb);
	ic6_copy = *ic6;

	ic4 = (struct icmphdr *)(skb->data + skb_transport_offset(skb));
	err = ipxl_64_icmp_info_type_code(&ic6_copy, ic4);
	if (unlikely(err))
		return err;

	ic4->checksum = ipxl_64_icmp_info_csum(in6, &ic6_copy, ic4,
					       ipxl_skb_datagram_len(skb));
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int ipxl_64_icmp_inner_info(struct sk_buff *skb,
				   unsigned int inner_l4_off)
{
	struct icmphdr *ic4;
	struct icmp6hdr ic6;
	int err;

	ic6 = *(struct icmp6hdr *)(skb->data + inner_l4_off);
	ic4 = (struct icmphdr *)(skb->data + inner_l4_off);
	err = ipxl_64_icmp_info_type_code(&ic6, ic4);
	if (unlikely(err))
		return err;

	ic4->checksum = 0;
	ic4->checksum = csum_fold(skb_checksum(skb, inner_l4_off,
					       skb->len - inner_l4_off, 0));
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int ipxl_64_icmp_inner_l4(struct sk_buff *skb, unsigned int inner_l4_off,
				 const struct iphdr *inner4,
				 const struct ipv6hdr *inner6)
{
	switch (inner4->protocol) {
	case IPPROTO_TCP:
		return ipxl_64_inner_tcp(skb, inner6, inner4,
					 (struct tcphdr *)(skb->data +
							   inner_l4_off));
	case IPPROTO_UDP:
		return ipxl_64_inner_udp(skb, inner6, inner4,
					 (struct udphdr *)(skb->data +
							   inner_l4_off));
	case IPPROTO_ICMP:
		return ipxl_64_icmp_inner_info(skb, inner_l4_off);
	default:
		return 0;
	}
}

static const u8 ipxl_64_icmp_ptrs[] = {
	0,  1,	0xff, 0xff, 2,	2,  9,	8,  12, 12, 12, 12, 12, 12,
	12, 12, 12,   12,   12, 12, 12, 12, 12, 12, 16, 16, 16, 16,
	16, 16, 16,   16,   16, 16, 16, 16, 16, 16, 16, 16,
};

static int ipxl_64_icmp_ptr_map(u32 ptr6, u32 *ptr4)
{
	if (unlikely(ptr6 >= ARRAY_SIZE(ipxl_64_icmp_ptrs) ||
		     ipxl_64_icmp_ptrs[ptr6] == 0xff))
		return -EPROTONOSUPPORT;

	*ptr4 = ipxl_64_icmp_ptrs[ptr6];
	return 0;
}

static __be16 ipxl_64_icmp_compute_mtu4(const struct ipxl_pkt_ctx *ctx,
					const struct sk_buff *skb,
					const struct icmp6hdr *ic6)
{
	unsigned int in_mtu, out_mtu, pkt_mtu;

	/* TODO: derive nexthop MTU from a post-translation IPv4 route lookup. */
	in_mtu = ctx->dev->mtu;
	out_mtu = ctx->dev->mtu;

	/* RFC7915 Section 5.2:
	 * min((PTB_mtu - 20), mtu4_nexthop, (mtu6_nexthop - 20))
	 */
	pkt_mtu = be32_to_cpu(ic6->icmp6_mtu);
	if (likely(pkt_mtu > 20))
		pkt_mtu -= 20;
	else
		pkt_mtu = 0;

	if (likely(out_mtu > 20))
		out_mtu -= 20;
	else
		out_mtu = 0;

	return cpu_to_be16(min3(pkt_mtu, out_mtu, in_mtu));
}

static int ipxl_64_icmp_errhdr_build4(const struct ipxl_pkt_ctx *ctx,
				      struct sk_buff *skb,
				      const struct icmp6hdr *ic6,
				      struct icmphdr *ic4,
				      enum ipxl_icmp_ie_policy *ie_policy)
{
	u32 ptr4;
	int err;

	switch (ic6->icmp6_type) {
	case ICMPV6_DEST_UNREACH:
		ic4->type = ICMP_DEST_UNREACH;
		switch (ic6->icmp6_code) {
		case ICMPV6_NOROUTE:
		case ICMPV6_NOT_NEIGHBOUR:
		case ICMPV6_ADDR_UNREACH:
			ic4->code = ICMP_HOST_UNREACH;
			break;
		case ICMPV6_ADM_PROHIBITED:
			ic4->code = ICMP_HOST_ANO;
			break;
		case ICMPV6_PORT_UNREACH:
			ic4->code = ICMP_PORT_UNREACH;
			break;
		default:
			return -EINVAL;
		}
		ic4->icmp4_unused = 0;
		*ie_policy = IPXL_ICMP_IE_ALLOWED;
		return 0;
	case ICMPV6_TIME_EXCEED:
		ic4->type = ICMP_TIME_EXCEEDED;
		ic4->code = ic6->icmp6_code;
		ic4->icmp4_unused = 0;
		*ie_policy = IPXL_ICMP_IE_ALLOWED;
		return 0;
	case ICMPV6_PKT_TOOBIG:
		ic4->type = ICMP_DEST_UNREACH;
		ic4->code = ICMP_FRAG_NEEDED;
		ic4->un.frag.__unused = 0;
		ic4->un.frag.mtu = ipxl_64_icmp_compute_mtu4(ctx, skb, ic6);
		*ie_policy = IPXL_ICMP_IE_FORBIDDEN;
		return 0;
	case ICMPV6_PARAMPROB:
		switch (ic6->icmp6_code) {
		case ICMPV6_HDR_FIELD:
			ic4->type = ICMP_PARAMETERPROB;
			ic4->code = 0;
			err = ipxl_64_icmp_ptr_map(be32_to_cpu(ic6->icmp6_dataun.un_data32
								       [0]),
						   &ptr4);
			if (unlikely(err))
				return err;
			ic4->icmp4_unused = cpu_to_be32(ptr4 << 24);
			break;
		case ICMPV6_UNK_NEXTHDR:
			ic4->type = ICMP_DEST_UNREACH;
			ic4->code = ICMP_PROT_UNREACH;
			ic4->icmp4_unused = 0;
			break;
		default:
			return -EINVAL;
		}
		*ie_policy = IPXL_ICMP_IE_FORBIDDEN;
		return 0;
	default:
		return -EINVAL;
	}
}

static int ipxl_64_icmp_inner(const struct ipxl_pkt_ctx *ctx,
			      struct sk_buff *skb, int *inner_delta)
{
	unsigned int old_prefix, new_prefix, inner_l3_len, inner_tot_len,
		inner_l4_len, outer_prefix_len, inner_l3_off, inner_l4_off;
	/* TODO: Consider isolating inner translation by temporarily pulling
	 * outer_prefix_len and operating on a pure "inner view". That could
	 * remove the need for outer header snapshot/restore here.
	 */
	const struct icmphdr outer_icmp4_copy = *icmp_hdr(skb);
	const struct iphdr outer4_copy = *ip_hdr(skb);
	const struct ipxl_cb *cb = ipxl_skb_cb(skb);
	bool has_inner_frag, first_inner_frag, df;
	struct frag_hdr inner_frag_copy;
	struct ipv6hdr inner6_copy;
	struct iphdr *inner4;
	int err;
	__be32 saddr, daddr;
	u8 inner_l4_proto;

	if (unlikely(!(cb->in_icmp_err)))
		return -EINVAL;

	inner_l3_off = cb->inner_l3_offset;
	inner_l4_off = cb->inner_l4_offset;
	if (unlikely(inner_l4_off < inner_l3_off))
		return -EINVAL;

	outer_prefix_len = inner_l3_off;
	inner6_copy = *(struct ipv6hdr *)(skb->data + outer_prefix_len);
	inner_l3_len = inner_l4_off - inner_l3_off;
	inner_l4_proto = ipxl_64_nexthdr_to_proto(cb->inner_l4_proto);
	has_inner_frag = !!cb->inner_fragh_off;
	first_inner_frag = true;
	if (unlikely(has_inner_frag)) {
		inner_frag_copy =
			*(struct frag_hdr *)(skb->data + cb->inner_fragh_off);
		first_inner_frag = ipxl_is_first_frag6(&inner_frag_copy);
	}

	inner_l4_len = first_inner_frag ? ipxl_l4_min_len(inner_l4_proto) : 0;
	if (unlikely(first_inner_frag &&
		     skb_ensure_writable(skb, inner_l4_off + inner_l4_len)))
		return -ENOMEM;

	err = ipxl_addrs_64(ctx->cfg, &inner6_copy, false, &saddr, &daddr);
	if (unlikely(err))
		return err;

	old_prefix = outer_prefix_len + inner_l3_len;
	new_prefix = outer_prefix_len + sizeof(struct iphdr);
	*inner_delta = (int)new_prefix - (int)old_prefix;

	skb_pull(skb, old_prefix);
	skb_push(skb, new_prefix);
	/* Outer 6->4 translation already set network/transport headers, but
	 * inner relayout pulls/pushes again and changes skb->data placement.
	 * Reinitialize outer header offsets so ip{,v6}_hdr()/icmp{,6}_hdr()
	 * and skb_transport_offset() keep pointing to the outer packet.
	 */
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	*ip_hdr(skb) = outer4_copy;
	*icmp_hdr(skb) = outer_icmp4_copy;

	inner4 = (struct iphdr *)(skb->data + outer_prefix_len);
	inner_tot_len = ntohs(inner6_copy.payload_len) + sizeof(inner6_copy) -
			inner_l3_len + sizeof(struct iphdr);
	/* RFC7915 Section 5.1 */
	if (likely(!has_inner_frag)) {
		df = inner_tot_len > (IPV6_MIN_MTU - sizeof(struct iphdr));
		inner4->frag_off = ipxl_build_frag4_offset(df, false, 0);
	} else {
		inner4->frag_off =
			ipxl_build_frag4_offset(false,
						!!(be16_to_cpu(inner_frag_copy
								       .frag_off) &
						   IP6_MF),
						ipxl_get_frag6_offset(&inner_frag_copy));
	}
	ipxl_64_build_l3(inner4, &inner6_copy, inner_tot_len, inner4->frag_off,
			 inner_l4_proto, saddr, daddr, inner6_copy.hop_limit,
			 has_inner_frag ?
				 cpu_to_be16(be32_to_cpu(inner_frag_copy.identification)) :
				 0);

	if (likely(!has_inner_frag)) {
		inner4->id = 0;
		__ip_select_ident(dev_net(ctx->dev), inner4, 1);
		inner4->check = 0;
		inner4->check = ip_fast_csum(inner4, inner4->ihl);
	}

	if (unlikely(!first_inner_frag))
		return 0;

	inner_l4_off = outer_prefix_len + sizeof(struct iphdr);
	return ipxl_64_icmp_inner_l4(skb, inner_l4_off, inner4, &inner6_copy);
}

static int ipxl_64_icmp_squeeze_extensions(struct sk_buff *skb,
					   unsigned int icmp6_ipl,
					   int inner_delta,
					   enum ipxl_icmp_ie_policy ie_policy)
{
	unsigned int outer_hdrs_len, payload_len, icmp4_iel_in, icmp4_iel_out,
		out_pad, max_iel, pkt_len_cap, icmp4_ipl_out_bytes,
		icmp4_ipl_out = 0;
	int icmp4_ipl_in_bytes, err;
	struct icmphdr *ic4;

	if (likely(!icmp6_ipl))
		goto no_extensions;

	/* outer IPv4 header + ICMPv4 header */
	outer_hdrs_len = skb_transport_offset(skb) + sizeof(struct icmphdr);
	if (unlikely(skb->len < outer_hdrs_len))
		return -EINVAL;

	/* inner packet bytes (+ optional extension bytes) */
	payload_len = skb->len - outer_hdrs_len;
	/* translated quoted-packet length in bytes */
	icmp4_ipl_in_bytes = (int)icmp6_ipl + inner_delta;
	if (unlikely(icmp4_ipl_in_bytes < 0 ||
		     (unsigned int)icmp4_ipl_in_bytes > payload_len))
		return -EINVAL;
	if (likely((unsigned int)icmp4_ipl_in_bytes == payload_len))
		goto no_extensions;

	icmp4_iel_in = payload_len - (unsigned int)icmp4_ipl_in_bytes;
	max_iel = IPXL_ICMP4_ERROR_MAX_LEN -
		  (outer_hdrs_len + ICMP_EXT_ORIG_DGRAM_MIN_LEN);

	if (unlikely(ie_policy == IPXL_ICMP_IE_FORBIDDEN)) {
		icmp4_ipl_out_bytes = (unsigned int)icmp4_ipl_in_bytes;
		out_pad = 0;
		icmp4_iel_out = 0;
	} else if (unlikely(icmp4_iel_in > max_iel)) {
		pkt_len_cap = min_t(unsigned int, skb->len - icmp4_iel_in,
				    IPXL_ICMP4_ERROR_MAX_LEN);
		icmp4_ipl_out_bytes = pkt_len_cap - outer_hdrs_len;
		out_pad = 0;
		icmp4_iel_out = 0;
		icmp4_ipl_out = 0;
	} else {
		pkt_len_cap =
			min_t(unsigned int, skb->len, IPXL_ICMP4_ERROR_MAX_LEN);
		icmp4_ipl_out_bytes =
			round_down(pkt_len_cap - icmp4_iel_in - outer_hdrs_len,
				   sizeof(u32));
		out_pad = max_t(unsigned int, ICMP_EXT_ORIG_DGRAM_MIN_LEN,
				icmp4_ipl_out_bytes) -
			  icmp4_ipl_out_bytes;
		icmp4_iel_out = icmp4_iel_in;
		/* RFC4884 field in 32-bit units (outer IPv4 ICMP errors) */
		icmp4_ipl_out = (icmp4_ipl_out_bytes + out_pad) >> 2;
	}

	if (unlikely(!pskb_may_pull(skb, skb->len)))
		return -ENOMEM;
	/* TODO: FORBIDDEN/no-extension paths only need header writes and
	 * possible trim; avoid requiring full-length writable skb there.
	 */
	err = skb_ensure_writable(skb, skb->len);
	if (unlikely(err))
		return err;

	err = ipxl_icmp_relayout(skb, outer_hdrs_len,
				 (unsigned int)icmp4_ipl_in_bytes, icmp4_iel_in,
				 icmp4_ipl_out_bytes, out_pad, icmp4_iel_out);
	if (unlikely(err))
		return err;

	ic4 = icmp_hdr(skb);
	if (ie_policy == IPXL_ICMP_IE_ALLOWED)
		ic4->icmp4_datagram_length = icmp4_ipl_out;
	goto trim_and_update;

no_extensions:
	if (ie_policy == IPXL_ICMP_IE_ALLOWED) {
		ic4 = icmp_hdr(skb);
		ic4->icmp4_datagram_length = 0;
	}

trim_and_update:
	if (unlikely(skb->len > IPXL_ICMP4_ERROR_MAX_LEN)) {
		err = pskb_trim(skb, IPXL_ICMP4_ERROR_MAX_LEN);
		if (unlikely(err))
			return err;
	}

	update_total_length(skb);
	return 0;
}

static int ipxl_64_icmp_error(const struct ipxl_pkt_ctx *ctx,
			      struct sk_buff *skb, const struct icmp6hdr *ic6)
{
	const struct ipxl_cb *cb = ipxl_skb_cb(skb);
	enum ipxl_icmp_ie_policy ie_policy;
	unsigned int icmp6_ipl;
	int inner_delta, err;
	struct icmphdr *ic4;

	if (unlikely(!(cb->in_icmp_err))) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return -EINVAL;
	}

	ic4 = (struct icmphdr *)(skb->data + skb_transport_offset(skb));
	err = ipxl_64_icmp_errhdr_build4(ctx, skb, ic6, ic4, &ie_policy);
	if (unlikely(err))
		return err;

	err = ipxl_64_icmp_inner(ctx, skb, &inner_delta);
	if (unlikely(err))
		return err;

	icmp6_ipl = ic6->icmp6_datagram_len << 3;
	err = ipxl_64_icmp_squeeze_extensions(skb, icmp6_ipl, inner_delta,
					      ie_policy);
	if (unlikely(err))
		return err;

	ipxl_64_icmp_compute_csum4(skb);
	return 0;
}

int ipxl_64_icmp(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb,
		 bool is_err, const struct icmp6hdr *ic6_copy,
		 const struct ipv6hdr *in6)
{
	if (unlikely(is_err))
		return ipxl_64_icmp_error(ctx, skb, ic6_copy);

	return ipxl_64_icmp_info(skb, in6);
}

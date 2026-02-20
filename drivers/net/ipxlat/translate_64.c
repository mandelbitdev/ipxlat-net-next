// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include <linux/icmpv6.h>
#include <net/ip.h>

#include "translate_64.h"
#include "address.h"
#include "packet.h"
#include "icmp_64.h"
#include "transport.h"

static u8 ipxl_64_nexthdr_to_proto(u8 nexthdr)
{
	return (nexthdr == NEXTHDR_ICMP) ? IPPROTO_ICMP : nexthdr;
}

void ipxl_64_build_l3(struct iphdr *iph4, const struct ipv6hdr *iph6,
		      unsigned int tot_len, __be16 frag_off, u8 protocol,
		      __be32 saddr, __be32 daddr, u8 ttl, __be16 id)
{
	iph4->version = 4;
	iph4->ihl = 5;
	iph4->tos = ipxl_get_ipv6_tclass(iph6);
	iph4->tot_len = cpu_to_be16(tot_len);
	iph4->frag_off = frag_off;
	iph4->ttl = ttl;
	iph4->protocol = protocol;
	iph4->saddr = saddr;
	iph4->daddr = daddr;
	iph4->id = id;
	iph4->check = 0;
	iph4->check = ip_fast_csum(iph4, iph4->ihl);
}

static __be16 ipxl_64_frag_off(const struct sk_buff *skb,
			       const struct frag_hdr *frag6, u8 l4_proto)
{
	bool df;

	if (frag6)
		return ipxl_build_frag4_offset(false,
					       !!(be16_to_cpu(frag6->frag_off) &
						  IP6_MF),
					       ipxl_get_frag6_offset(frag6));

	if (skb_has_frag_list(skb))
		return ipxl_build_frag4_offset(false, false, 0);

	if (skb_is_gso(skb)) {
		df = (l4_proto == IPPROTO_TCP) &&
		     (ipxl_skb_cb(skb)->payload_off +
			      skb_shinfo(skb)->gso_size >
		      (IPV6_MIN_MTU - sizeof(struct iphdr)));
		return ipxl_build_frag4_offset(df, false, 0);
	}

	return ipxl_build_frag4_offset(skb->len > (IPV6_MIN_MTU -
						   sizeof(struct iphdr)),
				       false, 0);
}

int ipxl_64_translate(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb)
{
	bool is_icmp6_err, has_frag, first_frag;
	struct ipxl_cb *cb = ipxl_skb_cb(skb);
	struct ipv6hdr in6 = *ipv6_hdr(skb);
	unsigned int min_l4_len, ip6_len;
	u8 l4_proto, out_l4_proto;
	struct frag_hdr frag_copy;
	struct icmp6hdr ic6_copy;
	struct frag_hdr *frag6;
	__be32 saddr, daddr;
	__be16 frag_off, id;
	struct iphdr *iph4;
	int l3_delta, err;

	/* snapshot original outer IPv6 fields before L3 rewrite */
	ip6_len = cb->l4_off;
	l4_proto = cb->l4_proto;
	out_l4_proto = ipxl_64_nexthdr_to_proto(l4_proto);
	is_icmp6_err = cb->in_icmp_err;
	frag6 = cb->fragh_off ?
			(struct frag_hdr *)(skb->data + cb->fragh_off) :
			NULL;
	has_frag = !!frag6;
	l3_delta = (int)sizeof(struct iphdr) - (int)ip6_len;

	if (unlikely(has_frag))
		frag_copy = *frag6;
	first_frag = ipxl_is_first_frag6(has_frag ? &frag_copy : NULL);
	if (unlikely(is_icmp6_err)) {
		if (unlikely(l4_proto != NEXTHDR_ICMP))
			return -EINVAL;

		ic6_copy = *icmp6_hdr(skb);
	}

	/* derive translated IPv4 endpoints */
	err = ipxl_addrs_64(ctx->cfg, &in6, is_icmp6_err, &saddr, &daddr);
	if (unlikely(err))
		return err;

	/* replace outer IPv6 hdr with IPv4 hdr in-place */
	if (unlikely(skb->ip_summed == CHECKSUM_COMPLETE))
		skb->ip_summed = CHECKSUM_NONE;
	skb_pull(skb, ip6_len);
	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	skb->protocol = htons(ETH_P_IP);

	/* Rebase cached offsets after L3 size delta.
	 * For outer 6->4 translation this should not underflow: cached offsets
	 * were built from l3_off + ip6_len (+ ...), and
	 * delta = sizeof(struct iphdr) - ip6_len, so ip6_len cancels out after
	 * rebasing. A failure here means internal metadata inconsistency, not a
	 * packet validation outcome.
	 */
	err = ipxl_cb_rebase_offsets(cb, l3_delta);
	if (unlikely(err)) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return err;
	}

	cb->l3_hdr_len = sizeof(struct iphdr);
	cb->fragh_off = 0;
	cb->l4_proto = out_l4_proto;
	if (unlikely(!ipxl_cb_offsets_valid(cb))) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return -EINVAL;
	}

	/* build outer IPv4 base hdr from translated IPv6 fields */
	iph4 = ip_hdr(skb);
	frag_off = ipxl_64_frag_off(skb, has_frag ? &frag_copy : NULL,
				    out_l4_proto);
	id = has_frag ? cpu_to_be16(be32_to_cpu(frag_copy.identification)) : 0;
	ipxl_64_build_l3(iph4, &in6, skb->len, frag_off, out_l4_proto, saddr,
			 daddr, in6.hop_limit - 1, id);

	if (!has_frag) {
		iph4->id = 0;
		__ip_select_ident(dev_net(ctx->dev), iph4, 1);
		iph4->check = 0;
		iph4->check = ip_fast_csum(iph4, iph4->ihl);
	}

	/* non-first fragments have no transport header to translate */
	if (unlikely(!first_frag))
		goto out;

	/* ensure transport bytes are writable before L4 csum/proto rewrites */
	min_l4_len = ipxl_l4_min_len(out_l4_proto);
	if (unlikely(skb_ensure_writable(skb, skb_transport_offset(skb) +
						      min_l4_len)))
		return -ENOMEM;

	/* translate transport hdr and pseudohdr dependent checksums */
	switch (out_l4_proto) {
	case IPPROTO_TCP:
		err = ipxl_64_tcp(skb, &in6, false);
		break;
	case IPPROTO_UDP:
		err = ipxl_64_udp(skb, &in6, false);
		break;
	case IPPROTO_ICMP:
		err = ipxl_64_icmp(ctx, skb, is_icmp6_err, &ic6_copy, &in6);
		break;
	default:
		err = 0;
		break;
	}
	if (unlikely(err)) {
		netdev_info(ctx->dev,
			    "6->4: l4 translation failed proto=%u err=%d\n",
			    l4_proto, err);
		return err;
	}

out:
	/* normalize checksum/offload metadata for the translated frame */
	return ipxl_64_offload_finalize(skb, out_l4_proto,
					ip_is_fragment(iph4));
}

// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include "packet.h"

#include <linux/icmp.h>
#include <net/route.h>

#include "types.h"
#include "log.h"
#include "translation_state.h"

#define skb_hdr_ptr(skb, offset, buffer) \
	skb_header_pointer(skb, offset, sizeof(buffer), &buffer)

static int ipxl_validate_icmp6_csum(struct sk_buff *skb);
static int ipxl_v6_l4hdr_len(struct sk_buff *skb, unsigned int l4_offset,
			     __u8 l4_proto, bool *has_inner);

static int ipxl_v6_l4hdr_len(struct sk_buff *skb, unsigned int l4_offset,
			     __u8 l4_proto, bool *has_inner)
{
	struct icmp6hdr icmp_buf, *icmp;
	struct tcphdr tcp_buf, *tcp;

	*has_inner = false;

	switch (l4_proto) {
	case NEXTHDR_TCP:
		tcp = skb_hdr_ptr(skb, l4_offset, tcp_buf);
		if (unlikely(!tcp))
			return -EINVAL;
		return tcp_hdr_len(tcp);
	case NEXTHDR_UDP:
		return sizeof(struct udphdr);
	case NEXTHDR_ICMP:
		icmp = skb_hdr_ptr(skb, l4_offset, icmp_buf);
		if (unlikely(!icmp))
			return -EINVAL;
		if (has_inner)
			*has_inner = icmpv6_is_err(icmp->icmp6_type);
		return sizeof(struct icmp6hdr);
	default:
		return 0;
	}
}

/*
 * Basic IPv6 header walk: parse only the packet starting at @l3_offset.
 * It does not inspect quoted inner packets carried by ICMP errors.
 */
static int ipxl_v6_summarize_basic(const struct ipxl_pkt_ctx *ctx,
				   struct sk_buff *skb, unsigned int l3_offset,
				   __u8 *l4_proto, unsigned int *fhdr_offset,
				   unsigned int *l4_offset,
				   unsigned int *payload_offset)
{
	unsigned int frag_hdr_off, exthdr_off;
	struct frag_hdr frag_buf, *frag;
	int l4hdr_off, l4hdr_len, err;
	struct ipv6hdr ip6_buf, *ip6;
	__be16 frag_off;
	bool first_frag;
	__u8 nexthdr;

	ip6 = skb_header_pointer(skb, l3_offset, sizeof(ip6_buf), &ip6_buf);
	if (unlikely(!ip6 || ip6->version != 6))
		return -EINVAL;

	frag_hdr_off = l3_offset;
	err = ipv6_find_hdr(skb, &frag_hdr_off, NEXTHDR_FRAGMENT, NULL, NULL);
	if (unlikely(err < 0 && err != -ENOENT))
		return -EINVAL;

	*fhdr_offset = 0;
	if (unlikely(err == NEXTHDR_FRAGMENT)) {
		frag = skb_hdr_ptr(skb, frag_hdr_off, frag_buf);
		if (unlikely(!frag))
			return -EINVAL;

		*fhdr_offset = frag_hdr_off;
		first_frag = is_first_frag6(frag);

		if (unlikely(frag->nexthdr == NEXTHDR_FRAGMENT)) {
			log_debug("Double fragment header.");
			return -EINVAL;
		}

		if (unlikely(ipv6_ext_hdr(frag->nexthdr))) {
			log_debug("There's an extension header (%u) after Fragment.",
				  frag->nexthdr);
			return -EPROTONOSUPPORT;
		}

		if (!first_frag) {
			*l4_proto = frag->nexthdr;
			*l4_offset = frag_hdr_off + sizeof(struct frag_hdr);
			*payload_offset = *l4_offset;
			return 0;
		}
	}

	nexthdr = ip6->nexthdr;
	exthdr_off = l3_offset + sizeof(struct ipv6hdr);
	l4hdr_off = ipv6_skip_exthdr(skb, exthdr_off, &nexthdr, &frag_off);
	if (unlikely(l4hdr_off < 0))
		return -EINVAL;

	*l4_proto = nexthdr;
	*l4_offset = l4hdr_off;
	*payload_offset = l4hdr_off;

	l4hdr_len = ipxl_v6_l4hdr_len(skb, l4hdr_off, nexthdr, NULL);
	if (unlikely(l4hdr_len < 0))
		return l4hdr_len;
	*payload_offset += l4hdr_len;

	return 0;
}

static int ipxl_v6_icmp_inner_need_pull(const struct ipxl_pkt_ctx *ctx,
					struct sk_buff *skb,
					unsigned int outer_payload_off)
{
	union {
		struct ipv6hdr ip6;
		struct frag_hdr frag;
		struct icmp6hdr icmp;
	} buffer;
	union {
		struct ipv6hdr *ip6;
		struct frag_hdr *frag;
		struct icmp6hdr *icmp;
	} ptr;

	unsigned int inner_fhdr_off, inner_l4_off, inner_payload_off;
	__u8 inner_l4_proto;
	bool first_frag;
	int error;

	ptr.ip6 = skb_hdr_ptr(skb, outer_payload_off, buffer.ip6);
	if (unlikely(!ptr.ip6))
		return -EINVAL;
	if (unlikely(ptr.ip6->version != 6)) {
		log_debug("Version is not 6.");
		return -EINVAL;
	}

	error = ipxl_v6_summarize_basic(ctx, skb, outer_payload_off,
					&inner_l4_proto, &inner_fhdr_off,
					&inner_l4_off, &inner_payload_off);
	if (unlikely(error))
		return error;

	if (unlikely(inner_fhdr_off)) {
		ptr.frag = skb_hdr_ptr(skb, inner_fhdr_off, buffer.frag);
		if (unlikely(!ptr.frag))
			return -EINVAL;
		first_frag = is_first_frag6(ptr.frag);
	} else {
		first_frag = true;
	}

	if (unlikely(first_frag && inner_l4_proto == NEXTHDR_ICMP)) {
		ptr.icmp = skb_hdr_ptr(skb, inner_l4_off, buffer.icmp);
		if (unlikely(!ptr.icmp))
			return -EINVAL;
		if (icmpv6_is_err(ptr.icmp->icmp6_type)) {
			log_debug("Packet inside packet inside packet.");
			return -EINVAL;
		}
	}

	return inner_payload_off;
}

static int ipxl_v6_parse_need_pull(const struct ipxl_pkt_ctx *ctx,
				   struct sk_buff *skb)
{
	struct ipv6hdr l3_hdr_buf, *l3_hdr;
	union {
		struct frag_hdr frag;
	} buffer;
	union {
		struct frag_hdr *frag;
	} ptr;
	unsigned int fragh_off, l4_off, payload_off, rh_off, pointer;
	struct ipxl_cb *cb;
	int inner_pull_len, l4_len, pull_len, flags, nexthdr, err;
	bool is_icmp_err;
	__u8 l4_proto;
	unsigned int l3_off;

	l3_off = skb_network_offset(skb);
	l3_hdr = skb_header_pointer(skb, l3_off, sizeof(l3_hdr_buf),
				    &l3_hdr_buf);
	if (unlikely(!l3_hdr))
		return -EINVAL;
	if (unlikely(l3_hdr->version != 6))
		return -EINVAL;
	cb = ipxl_skb_cb(skb);
	cb->flags = 0;

	/* RFC7915 §4.1 */
	if (unlikely(l3_hdr->hop_limit <= 1))
		return ipxl_drop_icmp(ctx, skb, ICMPV6_TIME_EXCEED,
				      ICMPV6_EXC_HOPLIMIT, 0);

	if (unlikely(skb->len !=
		     sizeof(*l3_hdr) + be16_to_cpu(l3_hdr->payload_len)))
		return -EINVAL;

	err = ipxl_v6_summarize_basic(ctx, skb, l3_off, &l4_proto, &fragh_off,
				      &l4_off, &payload_off);
	if (unlikely(err == -EPROTONOSUPPORT))
		return ipxl_drop_icmp(ctx, skb, ICMPV6_DEST_UNREACH,
				      ICMPV6_ADM_PROHIBITED, 0);
	if (unlikely(err))
		return err;

	rh_off = 0;
	flags = IP6_FH_F_SKIP_RH;
	nexthdr = ipv6_find_hdr(skb, &rh_off, NEXTHDR_ROUTING, NULL, &flags);
	if (unlikely(nexthdr < 0 && nexthdr != -ENOENT))
		return -EINVAL;
	if (unlikely(nexthdr == NEXTHDR_ROUTING)) {
		pointer = rh_off + offsetof(struct ipv6_rt_hdr, segments_left);
		return ipxl_drop_icmp(ctx, skb, ICMPV6_PARAMPROB,
				      ICMPV6_HDR_FIELD, pointer);
	}

	pull_len = payload_off;
	if (unlikely(l4_proto == NEXTHDR_ICMP)) {
		/* RFC 7915 deprecates generating IPv6 atomic fragments
		 * (Section 2, Changes from RFC 6145) and says to avoid adding
		 * Fragment Header to non-fragmented packets (Section 4.1).
		 * If a Fragment Header is present on input, translation still
		 * follows Fragment processing rules (Section 5.1.1), so header
		 * presence alone is insufficient. We must inspect Fragment
		 * fields and distinguish real fragmentation from atomic
		 * fragments.
		 */
		if (unlikely(fragh_off)) {
			ptr.frag = skb_hdr_ptr(skb, fragh_off, buffer.frag);
			if (unlikely(!ptr.frag))
				return -EINVAL;
			if (unlikely(ip6_is_fragment(ptr.frag))) {
				log_debug("Packet is fragmented and ICMP; ICMP checksum cannot be translated.");
				return -EINVAL;
			}
		}

		l4_len = ipxl_v6_l4hdr_len(skb, l4_off, l4_proto, &is_icmp_err);
		if (unlikely(l4_len < 0))
			return l4_len;
		if (unlikely(is_icmp_err)) {
			cb->flags |= IPXLAT_SKB_F_ICMP_ERR;

			inner_pull_len =
				ipxl_v6_icmp_inner_need_pull(ctx, skb,
							     payload_off);
			if (unlikely(inner_pull_len < 0))
				return inner_pull_len;
			pull_len = inner_pull_len;
		}
	}

	cb->l4_proto = l4_proto;
	cb->l4_off = l4_off;
	cb->fragh_off = fragh_off;
	cb->payload_off = payload_off;
	cb->l3_hdr_len = l4_off - skb_network_offset(skb);

	return pull_len;
}

/* Validate IPv6 input and populate parser metadata in skb->cb. */
int ipxl_v6_validate(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb)
{
	struct ipxl_cb *cb;
	int pull_len, err;

	if (unlikely(skb_shared(skb))) {
		netdev_dbg(ctx->dev, "6->4: input skb is shared\n");
		return -EINVAL;
	}

	pull_len = ipxl_v6_parse_need_pull(ctx, skb);
	if (unlikely(pull_len < 0)) {
		netdev_dbg(ctx->dev, "6->4: failed to validate input packet\n");
		return pull_len;
	}

	if (unlikely(!pskb_may_pull(skb, pull_len))) {
		netdev_dbg(ctx->dev,
			   "6->4: failed to pull skb up to required offset (%u)\n",
			   pull_len);
		return -ENOMEM;
	}

	cb = ipxl_skb_cb(skb);
	skb_set_transport_header(skb, cb->l4_off);

	if (unlikely(cb->flags & IPXLAT_SKB_F_ICMP_ERR)) {
		if (unlikely(cb->l4_proto != NEXTHDR_ICMP)) {
			DEBUG_NET_WARN_ON_ONCE(1);
			return -EINVAL;
		}

		/* The translated ICMPv4 checksum is recomputed from scratch,
		 * so reject bad ICMPv6 error checksums before conversion.
		 */
		err = ipxl_validate_icmp6_csum(skb);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static bool ipxl_addr4_valid(__be32 addr4)
{
	return !(ipv4_is_zeronet(addr4) || ipv4_is_loopback(addr4) ||
		 ipv4_is_multicast(addr4) || ipv4_is_lbcast(addr4));
}

enum ipxl_srr_state {
	IPXL_SRR_NONE,
	IPXL_SRR_UNEXPIRED,
	IPXL_SRR_EXPIRED,
	IPXL_SRR_MALFORMED,
};

/*
 * RFC 7915 Section 4.1 requires ignoring IPv4 options unless an unexpired
 * LSRR/SSRR is present, in which case we must send ICMPv4 SR_FAILED.
 * We intentionally treat malformed option encoding as invalid input and
 * return IPXL_SRR_MALFORMED to drop early instead of continuing translation.
 */
static enum ipxl_srr_state ipxl_v4_srr_state(const struct iphdr *hdr)
{
	const unsigned char *opt, *end;
	__u8 type, len, ptr;

	if (likely(hdr->ihl <= 5))
		return IPXL_SRR_NONE;

	opt = (const unsigned char *)(hdr + 1);
	end = ((const unsigned char *)hdr) + (hdr->ihl << 2);

	while (opt < end) {
		type = opt[0];
		if (type == IPOPT_END)
			return IPXL_SRR_NONE;
		if (type == IPOPT_NOOP) {
			opt++;
			continue;
		}

		/* for any option except EOL/NOOP you must read at least the
		 * type and the len
		 */
		if (unlikely(end - opt < 2))
			return IPXL_SRR_MALFORMED;

		len = opt[1];
		if (unlikely(len < 2 || opt + len > end))
			return IPXL_SRR_MALFORMED;

		if (type == IPOPT_LSRR || type == IPOPT_SSRR) {
			if (unlikely(len < 3))
				return IPXL_SRR_MALFORMED;

			/* points to the beginning of the next IP addr */
			ptr = opt[2];
			if (unlikely(ptr < 4))
				return IPXL_SRR_MALFORMED;
			if (unlikely(ptr > len))
				return IPXL_SRR_EXPIRED;
			if (unlikely(ptr > len - 3))
				return IPXL_SRR_MALFORMED;

			return IPXL_SRR_UNEXPIRED;
		}

		opt += len;
	}

	return IPXL_SRR_NONE;
}

static int ipxl_v4_outer_l3hdr_len(struct sk_buff *skb, unsigned int l3_offset)
{
	const struct iphdr *iph;
	struct iphdr _iph;
	int l3_len;

	iph = skb_header_pointer(skb, l3_offset, sizeof(_iph), &_iph);
	if (unlikely(!iph || iph->version != 4 || iph->ihl < 5))
		return -EINVAL;

	l3_len = iph->ihl << 2;
	if (unlikely(iph_totlen(skb, iph) < l3_len))
		return -EINVAL;

	return l3_len;
}

/* same thing as ipxl_v4_outer_l3hdr_len but uses ntohs(iph->tot_len) instead of
 * iph_totlen because if the inner packet has tot_len == 0 we don't want to
 * fallback to the outer packet's GSO metadata
 */
static int ipxl_v4_inner_l3hdr_len(struct sk_buff *skb, unsigned int l3_offset)
{
	const struct iphdr *iph;
	struct iphdr _iph;
	int l3_len;

	iph = skb_header_pointer(skb, l3_offset, sizeof(_iph), &_iph);
	if (unlikely(!iph || iph->version != 4 || iph->ihl < 5))
		return -EINVAL;

	l3_len = iph->ihl << 2;
	if (unlikely(ntohs(iph->tot_len) < l3_len))
		return -EINVAL;

	return l3_len;
}

static int ipxl_v4_l4hdr_len(struct sk_buff *skb, unsigned int l4_offset,
			     __u8 l4_proto, bool *has_inner,
			     __u16 *udp_zero_csum_len, bool fragmented,
			     bool compute_udp_csum_zero, bool allow_udp_trunc,
			     bool *udp_zero_reject)
{
	struct icmphdr icmph_buf, *icmph;
	struct tcphdr tcph_buf, *tcph;
	struct udphdr udph_buf, *udph;
	unsigned int l4_len;

	*has_inner = false;
	*udp_zero_csum_len = 0;
	*udp_zero_reject = false;

	switch (l4_proto) {
	case IPPROTO_TCP:
		tcph = skb_header_pointer(skb, l4_offset, sizeof(tcph_buf),
					  &tcph_buf);
		if (unlikely(!tcph))
			return -EINVAL;

		return tcp_hdr_len(tcph);
	case IPPROTO_UDP:
		udph = skb_header_pointer(skb, l4_offset, sizeof(udph_buf),
					  &udph_buf);
		if (unlikely(!udph))
			return -EINVAL;
		if (unlikely(udph->check == 0)) {
			if (allow_udp_trunc)
				return sizeof(struct udphdr);

			if (unlikely(fragmented || !compute_udp_csum_zero)) {
				*udp_zero_reject = true;
				return sizeof(struct udphdr);
			}

			l4_len = ntohs(udph->len);
			if (unlikely(l4_len > skb->len - l4_offset))
				return -EINVAL;
			if (unlikely(l4_len < sizeof(*udph)))
				return -EINVAL;
			*udp_zero_csum_len = l4_len;
		}

		return sizeof(struct udphdr);
	case IPPROTO_ICMP:
		icmph = skb_header_pointer(skb, l4_offset, sizeof(icmph_buf),
					   &icmph_buf);
		if (unlikely(!icmph))
			return -EINVAL;

		*has_inner = icmp_is_err(icmph->type);
		return sizeof(struct icmphdr);
	default:
		return 0;
	}
}

static int ipxl_v4_icmp_inner_need_pull(const struct ipxl_pkt_ctx *ctx,
					struct sk_buff *skb,
					unsigned int inner_l3_off)
{
	unsigned char inner_l3_buf[sizeof(struct iphdr) + MAX_IPOPTLEN];
	const struct iphdr *inner_l3_hdr;
	bool has_inner, udp_zero_reject;
	int inner_l3_len, inner_l4_len;
	unsigned int inner_l4_off;
	struct ipxl_cb *cb;

	inner_l3_len = ipxl_v4_inner_l3hdr_len(skb, inner_l3_off);
	if (unlikely(inner_l3_len < 0))
		return inner_l3_len;

	inner_l3_hdr = skb_header_pointer(skb, inner_l3_off, inner_l3_len,
					  inner_l3_buf);
	if (unlikely(!inner_l3_hdr))
		return -EINVAL;

	/* TODO: note that we're allowing non-first fragment in the inner
	 * packet on purpose even though those are highly unlikely
	 */
	cb = ipxl_skb_cb(skb);
	inner_l4_off = inner_l3_off + inner_l3_len;
	cb->inner_l3_offset = inner_l3_off;
	cb->inner_l3_hdr_len = inner_l3_len;
	cb->inner_l4_offset = inner_l4_off;
	cb->inner_udp_zero_csum_len = 0;

	if (unlikely(inner_l3_hdr->frag_off & htons(IP_OFFSET)))
		return inner_l4_off;

	inner_l4_len = ipxl_v4_l4hdr_len(skb, inner_l4_off,
					 inner_l3_hdr->protocol, &has_inner,
					 &cb->inner_udp_zero_csum_len,
					 ip_is_fragment(inner_l3_hdr),
					 ctx->cfg->compute_udp_csum_zero, true,
					 &udp_zero_reject);
	if (unlikely(inner_l4_len < 0))
		return inner_l4_len;
	if (unlikely(has_inner))
		return -EINVAL;
	if (unlikely(udp_zero_reject))
		return -EINVAL;

	return inner_l4_off + inner_l4_len;
}

static int ipxl_v4_parse_need_pull(const struct ipxl_pkt_ctx *ctx,
				   struct sk_buff *skb)
{
	unsigned char l3_buf[sizeof(struct iphdr) + MAX_IPOPTLEN];
	struct ipxl_cb *cb = ipxl_skb_cb(skb);
	int l3_len, l4_len, pull_len;
	unsigned int l3_off, l4_off;
	const struct iphdr *l3_hdr;
	enum ipxl_srr_state srr;
	bool is_icmp_err, udp_zero_reject;

	l3_off = skb_network_offset(skb);
	/* get the actual length of the IP header including option */
	l3_len = ipxl_v4_outer_l3hdr_len(skb, l3_off);
	if (unlikely(l3_len < 0))
		return l3_len;

	/* fetch the complete IP header */
	l3_hdr = skb_header_pointer(skb, l3_off, l3_len, l3_buf);
	if (unlikely(!l3_hdr))
		return -EINVAL;

	/* validate the addresses */
	if (unlikely(!ipxl_addr4_valid(l3_hdr->saddr) ||
		     !ipxl_addr4_valid(l3_hdr->daddr)))
		return -EINVAL;

	/* RFC7915 §4.1 */
	srr = ipxl_v4_srr_state(l3_hdr);
	if (unlikely(srr == IPXL_SRR_MALFORMED))
		return -EINVAL;
	if (unlikely(srr == IPXL_SRR_UNEXPIRED))
		return ipxl_drop_icmp(ctx, skb, ICMP_DEST_UNREACH,
				      ICMP_SR_FAILED, 0);
	if (unlikely(l3_hdr->ttl <= 1))
		return ipxl_drop_icmp(ctx, skb, ICMP_TIME_EXCEEDED,
				      ICMP_EXC_TTL, 0);

	cb->l3_hdr_len = l3_len;
	cb->l4_proto = l3_hdr->protocol;
	cb->fragh_off = 0;
	cb->udp_zero_csum_len = 0;

	l4_off = l3_off + l3_len;
	cb->l4_off = l4_off;
	cb->payload_off = l4_off;
	pull_len = l4_off;

	/* RFC7915 §1.2 */
	if (unlikely(l3_hdr->protocol == IPPROTO_ICMP &&
		     ip_is_fragment(l3_hdr)))
		return -EINVAL;

	/* only non fragmented packets or first fragments have transport hdrs */
	if (unlikely(l3_hdr->frag_off & htons(IP_OFFSET)))
		return pull_len;

	/* validate transport header */
	l4_len = ipxl_v4_l4hdr_len(skb, l4_off, l3_hdr->protocol, &is_icmp_err,
				   &cb->udp_zero_csum_len,
				   ip_is_fragment(l3_hdr),
				   ctx->cfg->compute_udp_csum_zero, false,
				   &udp_zero_reject);
	if (unlikely(udp_zero_reject))
		return ipxl_drop_icmp(ctx, skb, ICMP_DEST_UNREACH,
				      ICMP_PKT_FILTERED, 0);
	if (unlikely(l4_len < 0))
		return l4_len;

	cb->payload_off = l4_off + l4_len;
	pull_len = cb->payload_off;

	if (unlikely(is_icmp_err)) {
		/* validate the quoted packet in an ICMP error */
		pull_len =
			ipxl_v4_icmp_inner_need_pull(ctx, skb, cb->payload_off);
		if (unlikely(pull_len < 0))
			return pull_len;
		cb->flags |= IPXLAT_SKB_F_ICMP4_ERR;
	}

	return pull_len;
}

static int ipxl_validate_icmp4_csum(struct sk_buff *skb)
{
	__sum16 csum;

	/* skip if checksum if not software-owned */
	if (skb->ip_summed != CHECKSUM_NONE)
		return 0;

	/* Compute the csum over ICMP message bytes: starts at transport hdr
	 * (ICMP hdr), length is ICMP hdr + ICMP payload. Then fold to 16-bit
	 * internet csum.
	 */
	csum = csum_fold(skb_checksum(skb, skb_transport_offset(skb),
				      skb_datagram_len(skb), 0));

	/* validate by checking if the folded result is 0 */
	return unlikely(csum) ? -EINVAL : 0;
}

static int ipxl_validate_icmp6_csum(struct sk_buff *skb)
{
	struct ipv6hdr *iph6;
	unsigned int len;
	__sum16 csum;

	if (skb->ip_summed != CHECKSUM_NONE)
		return 0;

	iph6 = ipv6_hdr(skb);
	len = skb_datagram_len(skb);
	csum = csum_ipv6_magic(&iph6->saddr, &iph6->daddr, len, NEXTHDR_ICMP,
			       skb_checksum(skb, skb_transport_offset(skb), len,
					    0));

	return unlikely(csum) ? -EINVAL : 0;
}

int ipxl_v4_validate(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb)
{
	struct ipxl_cb *cb;
	int pull_len, err;

	if (unlikely(skb_shared(skb))) {
		netdev_dbg(ctx->dev, "4->6: input skb is shared\n");
		return -EINVAL;
	}

	pull_len = ipxl_v4_parse_need_pull(ctx, skb);
	if (unlikely(pull_len < 0)) {
		netdev_dbg(ctx->dev, "4->6: failed to validate input packet\n");
		return pull_len;
	}

	if (unlikely(!pskb_may_pull(skb, pull_len))) {
		netdev_dbg(ctx->dev,
			   "4->6: failed to pull skb up to required offset (%u)\n",
			   pull_len);
		return -ENOMEM;
	}

	cb = ipxl_skb_cb(skb);
	skb_set_transport_header(skb, cb->l4_off);

	if (unlikely(cb->flags & IPXLAT_SKB_F_ICMP4_ERR)) {
		if (unlikely(cb->l4_proto != IPPROTO_ICMP)) {
			DEBUG_NET_WARN_ON_ONCE(1);
			return -EINVAL;
		}

		/* Translation path recomputes ICMPv6 checksum from scratch.
		 * Validate here so a corrupted ICMPv4 error is not converted
		 * into a translated packet with a valid checksum.
		 */
		err = ipxl_validate_icmp4_csum(skb);
		if (unlikely(err))
			return err;
	}
	return 0;
}

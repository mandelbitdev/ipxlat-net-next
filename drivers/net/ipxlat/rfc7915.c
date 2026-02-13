// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include "rfc7915.h"

#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/version.h>
#include <linux/minmax.h>

#include <net/ip.h>
#include <net/ip6_route.h>
#include <net/ip6_checksum.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/addrconf.h>
#include <net/dst_metadata.h>

#include "icmp.h"
#include "log.h"
#include "address.h"
#include "packet.h"
#include "translation_state.h"
#include "types.h"

/**
 * enum ipxl_icmp_ie_policy - RFC4884 ICMP extension handling policy
 * @IPXL_ICMP_IE_ALLOWED: preserve and translate extension layout metadata
 * @IPXL_ICMP_IE_FORBIDDEN: drop extension area and clear extension metadata
 *
 * Controls whether ICMP extension bytes (the IE area that follows the quoted
 * packet payload) are kept when translating ICMP error packets. This policy
 * is selected from mapped ICMP type/code semantics and then applied during
 * payload relayout.
 */
enum ipxl_icmp_ie_policy {
	IPXL_ICMP_IE_ALLOWED = 0,
	IPXL_ICMP_IE_FORBIDDEN = 1,
};

#define IPXL_ICMP4_ERROR_MAX_LEN 576U

static int ipxl_set_partial_csum(struct sk_buff *skb, __u16 csum_offset)
{
	if (likely(skb_partial_csum_set(skb, skb_transport_offset(skb),
					csum_offset)))
		return 0;
	return -EINVAL;
}

/*
 * Use this when header and payload both changed completely, so we gotta just
 * trash the old checksum and start anew.
 */
static void ipxl_compute_icmp4_csum(struct sk_buff *skb)
{
	struct icmphdr *hdr = icmp_hdr(skb);

	/*
	 * This function only gets called for ICMP error checksums, so
	 * skb_datagram_len() is fine.
	 */
	hdr->checksum = 0;
	hdr->checksum = csum_fold(skb_checksum(skb, skb_transport_offset(skb),
					       skb_datagram_len(skb), 0));
	skb->ip_summed = CHECKSUM_NONE;
}

/*
 * One-liner for creating the Identification field of the IPv6 Fragment header.
 */
static inline __be32 build_id_field(const struct iphdr *hdr4)
{
	return cpu_to_be32(be16_to_cpu(hdr4->id));
}

static u8 ipxlat_proto2nexthdr(u8 protocol)
{
	return (protocol == IPPROTO_ICMP) ? NEXTHDR_ICMP : protocol;
}

static inline void ipxl_v6_frag_from_v4(struct frag_hdr *fh6,
					const struct iphdr *hdr4, __u8 l4_proto)
{
	fh6->nexthdr = ipxlat_proto2nexthdr(l4_proto);
	fh6->reserved = 0;
	fh6->frag_off = build_v6_frag_offset(get_v4_frag_offset(hdr4),
					     is_mf_set_ipv4(hdr4));
	fh6->identification = build_id_field(hdr4);
}

/*
 * Update L4 checksum when translating from IPv4 to IPv6 for
 * non-CHECKSUM_PARTIAL skbs.
 *
 * The TCP/UDP checksum calculation is:
 * checksum = ~(pseudoheader + header + payload) folded to 16 bits
 *
 * For IPv4 pseudoheader: src(32) + dst(32) + zero(8) + proto(8) + tcp/udp_len(16)
 * For IPv6 pseudoheader: src(128) + dst(128) + tcp/udp_len(32) + zero(24) + next_hdr(8)
 * Where tcp/udp_len is the length of the transport header + payload.
 *
 * Given input: csum16 = ~(IPv4_pseudo + L4_in + payload) (folded)
 * Desired output: ~(IPv6_pseudo + L4_out + payload) (folded)
 *
 * We can transform by:
 * 1. Unfold and negate csum16 to get: IPv4_pseudo + L4_in + payload
 * 2. Subtract IPv4_pseudo contribution
 * 3. Subtract L4_in header contribution (only payload remains)
 * 4. Add IPv6_pseudo contribution
 * 5. Add L4_out header contribution
 * 6. Fold back to 16 bits and negate
 */
static __sum16 update_csum_4to6(__sum16 csum16, const struct iphdr *in_ip4,
				const void *in_l4_hdr,
				const struct ipv6hdr *out_ip6,
				const void *out_l4_hdr, size_t l4_hdr_len)
{
	__wsum csum, pseudohdr_csum;

	/* csum_unfold is a type conversion helper.
	 * We negate it to move from stored checksum form to "workable sum for
	 * arithmetic"-form.
	 *
	 * Input csum16 is folded and inverted, so ~csum_unfold(csum16) gives:
	 * IPv4_pseudo + L4_in + payload
	 */
	csum = ~csum_unfold(csum16);

	/* csum_tcpudp_nofold: Computes IPv4 pseudoheader checksum contribution
	 * Returns 32-bit checksum of: saddr + daddr + (proto << 8) + len
	 *
	 * We pass len=0 and proto=0 to get ONLY the address contribution.
	 * For TCP/UDP translation, pseudo-header len/proto are unchanged across
	 * v4<->v6, so they cancel in incremental update.
	 */
	pseudohdr_csum =
		csum_tcpudp_nofold(in_ip4->saddr, in_ip4->daddr, 0, 0, 0);

	/* csum_sub(csum, addend): Subtract addend from csum
	 * Implemented as csum_add(csum, ~addend)
	 *
	 * Remove IPv4 pseudoheader contribution from the checksum
	 * Result: L4_in + payload
	 */
	csum = csum_sub(csum, pseudohdr_csum);

	/* csum_partial: Compute checksum of in_l4_hdr bytes starting from 0
	 * Returns 32-bit partial checksum (not yet folded)
	 *
	 * Remove the L4 header contribution (source/dest ports, seq/ack, flags, etc.)
	 * Note: in_l4_hdr->check is 0 in callers that use this helper.
	 * Result: payload only
	 */
	csum = csum_sub(csum, csum_partial(in_l4_hdr, l4_hdr_len, 0));

	/* csum_ipv6_magic: Computes IPv6 pseudoheader checksum and folds it to 16 bits
	 * Returns ~folded(IPv6_pseudo + csum)
	 *
	 * We pass len=0 and proto=0 to get ONLY the address contribution
	 *
	 * The result is folded and inverted, so we need to unfold it and negate it
	 */
	pseudohdr_csum =
		~csum_unfold(csum_ipv6_magic(&out_ip6->saddr, &out_ip6->daddr,
					     0, 0, 0));

	/* Add IPv6 pseudoheader contribution
	 * Result: IPv6_pseudo + payload
	 */
	csum = csum_add(csum, pseudohdr_csum);

	/* Add new L4 header contribution (out_l4_hdr->check is 0)
	 * Result: IPv6_pseudo + L4_out + payload
	 */
	csum = csum_add(csum, csum_partial(out_l4_hdr, l4_hdr_len, 0));

	/* csum_fold: Fold 32-bit checksum to 16 bits
	 *
	 * Folds all carries into the lower 16 bits and adds the final ~
	 * Result: ~(IPv6_pseudo + L4_out + payload) folded to 16 bits
	 * This is the correct L4 checksum for the IPv6 packet
	 */
	return csum_fold(csum);
}

/* TODO: Revisit pool6791v4 source-address operational model.
 * __icmp_send_force lets us emit ICMPv4 with a forced translator source that
 * might not be locally assigned. This can require routing exceptions.
 * Prefer documenting or enforcing that pool6791v4 is locally owned/routable by
 * the translator.
 */
static void ipxl_46_icmp_err(const struct ipxl_pkt_ctx *ctx,
			     struct sk_buff *inner)
{
	struct inet_skb_parm parm = { 0 };
	struct ipxl_cb *cb;

	cb = ipxl_skb_cb(inner);
	log_debug("Sending ICMPv4 error.");
	__icmp_send_force(inner, cb->icmp_err.type, cb->icmp_err.code,
			  htonl(cb->icmp_err.info), &parm,
			  ctx->cfg->pool6791v4.s_addr);
}

static __u8 nexthdr2proto(__u8 nexthdr)
{
	return (nexthdr == NEXTHDR_ICMP) ? IPPROTO_ICMP : nexthdr;
}

static void update_total_length(struct sk_buff const *out)
{
	unsigned int new_len;
	struct iphdr *hdr;

	hdr = ip_hdr(out);
	new_len = out->len;

	if (be16_to_cpu(hdr->tot_len) == new_len)
		return;

	hdr->tot_len = cpu_to_be16(new_len);
	/* Assumes new_len <= (IPV6_MIN_MTU - sizeof(struct iphdr)) */
	hdr->frag_off &= cpu_to_be16(~IP_DF);
	hdr->check = 0;
	hdr->check = ip_fast_csum(hdr, hdr->ihl);
}

static __wsum pseudohdr6_csum(struct ipv6hdr const *hdr)
{
	return ~csum_unfold(csum_ipv6_magic(&hdr->saddr, &hdr->daddr, 0, 0, 0));
}

static __wsum pseudohdr4_csum(struct iphdr const *hdr)
{
	return csum_tcpudp_nofold(hdr->saddr, hdr->daddr, 0, 0, 0);
}

static __sum16 update_csum_6to4(__sum16 csum16, struct ipv6hdr const *in_ip6,
				void const *in_l4_hdr, size_t in_l4_hdr_len,
				struct iphdr const *out_ip4,
				void const *out_l4_hdr, size_t out_l4_hdr_len)
{
	__wsum csum;

	csum = ~csum_unfold(csum16);

	/*
	 * Regarding the pseudoheaders:
	 * The length is pretty hard to obtain if there's TCP and fragmentation,
	 * and whatever it is, it's not going to change. Therefore, instead of
	 * computing it only to cancel it out with itself later, simply sum
	 * (and substract) zero.
	 * Do the same with proto since we're feeling ballsy.
	 */

	/* Remove the IPv6 crap. */
	csum = csum_sub(csum, pseudohdr6_csum(in_ip6));
	csum = csum_sub(csum, csum_partial(in_l4_hdr, in_l4_hdr_len, 0));

	/* Add the IPv4 crap. */
	csum = csum_add(csum, pseudohdr4_csum(out_ip4));
	csum = csum_add(csum, csum_partial(out_l4_hdr, out_l4_hdr_len, 0));

	return csum_fold(csum);
}

static void ipxl_64_icmp_err(const struct ipxl_pkt_ctx *ctx,
			     struct sk_buff *inner)
{
	struct inet6_skb_parm parm = { 0 };
	struct in6_addr saddr;
	struct ipxl_cb *cb;
	__u8 code, type;
	__u32 info;

	cb = ipxl_skb_cb(inner);
	type = cb->icmp_err.type;
	code = cb->icmp_err.code;
	info = cb->icmp_err.info;
	saddr = ctx->cfg->icmp6err_saddr;
	icmp6_send(inner, type, code, info, &saddr, &parm);
}

static enum ipxl_xlat_action ipxl_xlat_64(const struct ipxl_pkt_ctx *ctx,
					  struct sk_buff *skb);
static enum ipxl_xlat_action ipxl_xlat_46(const struct ipxl_pkt_ctx *ctx,
					  struct sk_buff *skb);

static enum ipxl_xlat_action ipxl_failed_action(struct sk_buff *skb)
{
	return ipxl_skb_cb(skb)->flags & IPXLAT_SKB_F_OUT_ICMP_ERR ?
		       IPXL_XLAT_ACT_ICMP_ERR :
		       IPXL_XLAT_ACT_DROP;
}

enum ipxl_xlat_action ipxl_xlat(const struct ipxl_pkt_ctx *ctx,
				struct sk_buff *skb)
{
	__u16 proto = ntohs(skb->protocol);

	memset(skb->cb, 0, sizeof(struct ipxl_cb));

	if (proto == ETH_P_IPV6)
		return ipxl_xlat_64(ctx, skb);
	else if (proto == ETH_P_IP)
		return ipxl_xlat_46(ctx, skb);
	else {
		netdev_dbg(ctx->dev, "Unsupported L3 proto: %u", proto);
		return IPXL_XLAT_ACT_DROP;
	}
}

int ipxl_emit_icmp_error(const struct ipxl_pkt_ctx *ctx, struct sk_buff *inner)
{
	int err;

	switch (ntohs(inner->protocol)) {
	case ETH_P_IPV6:
		ipxl_64_icmp_err(ctx, inner);
		err = 0;
		break;
	case ETH_P_IP:
		ipxl_46_icmp_err(ctx, inner);
		err = 0;
		break;
	default:
		err = -EINVAL;
		DEBUG_NET_WARN_ON_ONCE(1);
		break;
	}
	return err;
}

static unsigned int ipxl_l4_min_len(__u8 protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return sizeof(struct tcphdr);
	case IPPROTO_UDP:
		return sizeof(struct udphdr);
	case IPPROTO_ICMP:
		return sizeof(struct icmphdr);
	}
	return 0;
}

static int ipxl_cb_rebase_offsets(struct ipxl_cb *cb, int delta)
{
	int off;

	off = cb->l4_off + delta;
	if (unlikely(off < 0))
		return -EINVAL;
	cb->l4_off = off;

	off = cb->payload_off + delta;
	if (unlikely(off < 0))
		return -EINVAL;
	cb->payload_off = off;

	if (unlikely(cb->flags & IPXLAT_SKB_F_IN_ICMP_ERR)) {
		off = cb->inner_l3_offset + delta;
		if (unlikely(off < 0))
			return -EINVAL;
		cb->inner_l3_offset = off;

		off = cb->inner_l4_offset + delta;
		if (unlikely(off < 0))
			return -EINVAL;
		cb->inner_l4_offset = off;

		if (cb->inner_fragh_off) {
			off = cb->inner_fragh_off + delta;
			if (unlikely(off < 0))
				return -EINVAL;
			cb->inner_fragh_off = off;
		}
	}

	return 0;
}

static bool ipxl_cb_offsets_valid(const struct ipxl_cb *cb)
{
	if (unlikely(cb->payload_off < cb->l4_off))
		return false;

	if (unlikely(cb->flags & IPXLAT_SKB_F_IN_ICMP_ERR)) {
		if (unlikely(cb->inner_l3_offset < cb->payload_off))
			return false;
		if (unlikely(cb->inner_l4_offset < cb->inner_l3_offset))
			return false;
		if (unlikely(cb->inner_fragh_off &&
			     cb->inner_fragh_off < cb->inner_l3_offset))
			return false;
		if (unlikely(cb->inner_fragh_off &&
			     cb->inner_fragh_off >= cb->inner_l4_offset))
			return false;
	}

	return true;
}

static __sum16 ipxl_l4_csum_ipv6(const struct in6_addr *saddr,
				 const struct in6_addr *daddr,
				 struct sk_buff *skb, unsigned int l4_off,
				 unsigned int l4_len, __u8 proto)
{
	return csum_ipv6_magic(saddr, daddr, l4_len, proto,
			       skb_checksum(skb, l4_off, l4_len, 0));
}

/* compute the complete on-wire ICMPv6 checksum */
static __sum16 ipxl_icmp6_csum(const struct ipv6hdr *iph6, struct sk_buff *skb)
{
	unsigned int len;

	len = skb_datagram_len(skb);
	return ipxl_l4_csum_ipv6(&iph6->saddr, &iph6->daddr, skb,
				 skb_transport_offset(skb), len,
				 IPPROTO_ICMPV6);
}

static int ipxl_finalize_offload_46(struct sk_buff *skb, __u8 l4_proto,
				    bool is_fragment)
{
	struct skb_shared_info *shinfo;

	if (unlikely(skb->ip_summed == CHECKSUM_COMPLETE))
		skb->ip_summed = CHECKSUM_NONE;

	if (!skb_is_gso(skb))
		goto out_hash;

	/* Align with forwarding paths that reject LRO skbs before xmit:
	 * net/ipv4/ip_forward.c, net/ipv6/ip6_output.c, br_forward.c.
	 */
	if (unlikely(skb_warn_if_lro(skb)))
		return -EINVAL;

	shinfo = skb_shinfo(skb);
	switch (l4_proto) {
	case IPPROTO_TCP:
		/* don't change the gso_size as we're not changing segment
		 * payload size
		 */
		if (shinfo->gso_type & SKB_GSO_TCPV4) {
			shinfo->gso_type &= ~SKB_GSO_TCPV4;
			shinfo->gso_type |= SKB_GSO_TCPV6;
		} else if (unlikely(!(shinfo->gso_type & SKB_GSO_TCPV6))) {
			/* TODO: is this really needed? */
			return -EOPNOTSUPP;
		}
		break;
	case IPPROTO_UDP:
		break;
	case IPPROTO_ICMP:
		/* ICMP has no GSO transform here; keep packet and clear stale
		 * offload metadata so the stack treats it as a normal frame.
		 */
		skb_gso_reset(skb);
		break;
	default:
		return -EPROTONOSUPPORT;
	}

out_hash:
	if (unlikely(is_fragment) ||
	    (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP))
		skb_clear_hash(skb);
	else
		skb_clear_hash_if_not_l4(skb);
	return 0;
}

static int ipxl_finalize_offload_64(struct sk_buff *skb, __u8 l4_proto,
				    bool is_fragment)
{
	struct skb_shared_info *shinfo;

	if (unlikely(skb->ip_summed == CHECKSUM_COMPLETE))
		skb->ip_summed = CHECKSUM_NONE;

	if (!skb_is_gso(skb))
		goto out_hash;

	/* Align with forwarding paths that reject LRO skbs before xmit:
	 * net/ipv4/ip_forward.c, net/ipv6/ip6_output.c, br_forward.c.
	 */
	if (unlikely(skb_warn_if_lro(skb)))
		return -EINVAL;

	shinfo = skb_shinfo(skb);
	switch (l4_proto) {
	case IPPROTO_TCP:
		/* don't change the gso_size as we're not changing segment
		 * payload size
		 */
		if (shinfo->gso_type & SKB_GSO_TCPV6) {
			shinfo->gso_type &= ~SKB_GSO_TCPV6;
			shinfo->gso_type |= SKB_GSO_TCPV4;
		} else if (unlikely(!(shinfo->gso_type & SKB_GSO_TCPV4))) {
			/* TODO: is this really needed? */
			return -EOPNOTSUPP;
		}
		break;
	case IPPROTO_UDP:
		break;
	case IPPROTO_ICMP:
		/* ICMP has no GSO transform here; keep packet and clear stale
		 * offload metadata so the stack treats it as a normal frame.
		 */
		skb_gso_reset(skb);
		break;
	default:
		return -EPROTONOSUPPORT;
	}

out_hash:
	if (unlikely(is_fragment ||
		     (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP)))
		skb_clear_hash(skb);
	else
		skb_clear_hash_if_not_l4(skb);

	return 0;
}

static int ipxl_tcp6_to_tcp4(struct sk_buff *skb, const struct ipv6hdr *in6,
			     bool inner)
{
	struct tcphdr tcp_old, *tcp_new;
	__sum16 csum16;

	tcp_new = tcp_hdr(skb);
	csum16 = tcp_new->check;
	tcp_old = *tcp_new;
	tcp_old.check = 0;

	if (!inner && skb->ip_summed == CHECKSUM_PARTIAL) {
		tcp_new->check = ~tcp_v4_check(skb_datagram_len(skb),
					       ip_hdr(skb)->saddr,
					       ip_hdr(skb)->daddr, 0);
		return ipxl_set_partial_csum(skb,
					     offsetof(struct tcphdr, check));
	}

	tcp_new->check = 0;
	tcp_new->check = update_csum_6to4(csum16, in6, &tcp_old,
					  sizeof(tcp_old), ip_hdr(skb), tcp_new,
					  sizeof(*tcp_new));
	if (!inner)
		skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int ipxl_inner_tcp6_to_tcp4(struct sk_buff *skb,
				   const struct ipv6hdr *in6,
				   const struct iphdr *out4,
				   struct tcphdr *tcp_new)
{
	struct tcphdr tcp_old;
	__sum16 csum16;

	csum16 = tcp_new->check;
	tcp_old = *tcp_new;
	tcp_old.check = 0;
	tcp_new->check = 0;
	tcp_new->check = update_csum_6to4(csum16, in6, &tcp_old,
					  sizeof(tcp_old), out4, tcp_new,
					  sizeof(*tcp_new));
	return 0;
}

static int ipxl_udp6_to_udp4(struct sk_buff *skb, const struct ipv6hdr *in6,
			     bool inner)
{
	struct udphdr udp_old, *udp_new;
	__sum16 csum16;

	udp_new = udp_hdr(skb);
	csum16 = udp_new->check;
	udp_old = *udp_new;
	udp_old.check = 0;

	if (!inner && skb->ip_summed == CHECKSUM_PARTIAL) {
		udp_new->check = ~udp_v4_check(skb_datagram_len(skb),
					       ip_hdr(skb)->saddr,
					       ip_hdr(skb)->daddr, 0);
		return ipxl_set_partial_csum(skb,
					     offsetof(struct udphdr, check));
	}

	udp_new->check = 0;
	udp_new->check = update_csum_6to4(csum16, in6, &udp_old,
					  sizeof(udp_old), ip_hdr(skb), udp_new,
					  sizeof(*udp_new));
	if (udp_new->check == 0)
		udp_new->check = CSUM_MANGLED_0;
	if (!inner)
		skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int ipxl_inner_udp6_to_udp4(struct sk_buff *skb,
				   const struct ipv6hdr *in6,
				   const struct iphdr *out4,
				   struct udphdr *udp_new)
{
	struct udphdr udp_old;
	__sum16 csum16;

	csum16 = udp_new->check;
	udp_old = *udp_new;
	udp_old.check = 0;
	udp_new->check = 0;
	udp_new->check = update_csum_6to4(csum16, in6, &udp_old,
					  sizeof(udp_old), out4, udp_new,
					  sizeof(*udp_new));
	if (udp_new->check == 0)
		udp_new->check = CSUM_MANGLED_0;
	return 0;
}

static int ipxl_icmp6_to_icmp4_info_type_code(const struct icmp6hdr *in,
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

static __sum16 ipxl_icmp6_to_icmp4_info_csum(const struct ipv6hdr *in6,
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

static int ipxl_icmp6_to_icmp4_info(struct sk_buff *skb,
				    const struct ipv6hdr *in6)
{
	struct icmp6hdr ic6_copy, *ic6;
	struct icmphdr *ic4;
	int err;

	ic6 = icmp6_hdr(skb);
	ic6_copy = *ic6;

	ic4 = (struct icmphdr *)(skb->data + skb_transport_offset(skb));
	err = ipxl_icmp6_to_icmp4_info_type_code(&ic6_copy, ic4);
	if (unlikely(err))
		return err;

	ic4->checksum = ipxl_icmp6_to_icmp4_info_csum(in6, &ic6_copy, ic4,
						       skb_datagram_len(skb));
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int ipxl_inner_icmp6_to_icmp4_info(struct sk_buff *skb,
					  unsigned int inner_l4_off)
{
	struct icmphdr *ic4;
	struct icmp6hdr ic6;
	int err;

	ic6 = *(struct icmp6hdr *)(skb->data + inner_l4_off);
	ic4 = (struct icmphdr *)(skb->data + inner_l4_off);
	err = ipxl_icmp6_to_icmp4_info_type_code(&ic6, ic4);
	if (unlikely(err))
		return err;

	ic4->checksum = 0;
	ic4->checksum = csum_fold(skb_checksum(skb, inner_l4_off,
					       skb->len - inner_l4_off, 0));
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int ipxl_inner_l4_64(struct sk_buff *skb, unsigned int inner_l4_off,
			    const struct iphdr *inner4,
			    const struct ipv6hdr *inner6)
{
	switch (inner4->protocol) {
	case IPPROTO_TCP:
		return ipxl_inner_tcp6_to_tcp4(skb, inner6, inner4,
					       (struct tcphdr *)(skb->data +
								 inner_l4_off));
	case IPPROTO_UDP:
		return ipxl_inner_udp6_to_udp4(skb, inner6, inner4,
					       (struct udphdr *)(skb->data +
								 inner_l4_off));
	case IPPROTO_ICMP:
		return ipxl_inner_icmp6_to_icmp4_info(skb, inner_l4_off);
	default:
		return 0;
	}
}

static int ipxl_icmp46_relayout(struct sk_buff *skb, unsigned int outer_len,
				unsigned int in_ipl, unsigned int in_iel,
				unsigned int out_ipl, unsigned int out_pad,
				unsigned int out_iel);

static const __u8 ipxl_icmp64_ptrs[] = {
	0,  1,	0xff, 0xff, 2,	2,  9,	8,  12, 12, 12, 12, 12, 12,
	12, 12, 12,   12,   12, 12, 12, 12, 12, 12, 16, 16, 16, 16,
	16, 16, 16,   16,   16, 16, 16, 16, 16, 16, 16, 16,
};

static int ipxl_icmp64_ptr6_to_ptr4(__u32 ptr6, __u32 *ptr4)
{
	if (unlikely(ptr6 >= ARRAY_SIZE(ipxl_icmp64_ptrs) ||
		     ipxl_icmp64_ptrs[ptr6] == 0xff))
		return -EPROTONOSUPPORT;

	*ptr4 = ipxl_icmp64_ptrs[ptr6];
	return 0;
}

static __be16 ipxl_icmp64_compute_mtu4(const struct ipxl_pkt_ctx *ctx,
				       const struct sk_buff *skb,
				       const struct icmp6hdr *ic6)
{
	unsigned int in_mtu, out_mtu, pkt_mtu;

	/* TODO: derive nexthop MTU from a post-translation IPv4 route lookup. */
	in_mtu = ctx->dev->mtu;
	out_mtu = ctx->dev->mtu;

	/* RFC7915 §5.2:
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

static int ipxl_icmp6_errhdr_to_icmp4(const struct ipxl_pkt_ctx *ctx,
				      struct sk_buff *skb,
				      const struct icmp6hdr *ic6,
				      struct icmphdr *ic4,
				      enum ipxl_icmp_ie_policy *ie_policy)
{
	__u32 ptr4;
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
		ic4->un.frag.mtu = ipxl_icmp64_compute_mtu4(ctx, skb, ic6);
		*ie_policy = IPXL_ICMP_IE_FORBIDDEN;
		return 0;
	case ICMPV6_PARAMPROB:
		switch (ic6->icmp6_code) {
		case ICMPV6_HDR_FIELD:
			ic4->type = ICMP_PARAMETERPROB;
			ic4->code = 0;
			err = ipxl_icmp64_ptr6_to_ptr4(be32_to_cpu(ic6->icmp6_dataun
									   .un_data32
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

static int ipxl_icmp_inner_6to4_xlate(const struct ipxl_pkt_ctx *ctx,
				      struct sk_buff *skb, int *inner_delta)
{
	const struct ipxl_cb *cb = ipxl_skb_cb(skb);
	unsigned int old_prefix, new_prefix, inner_l3_len, inner_tot_len;
	unsigned int inner_l4_len, outer_prefix_len;
	/* TODO: Consider isolating inner translation by temporarily pulling
	 * outer_prefix_len and operating on a pure "inner view". That could
	 * remove the need for outer header snapshot/restore here.
	 */
	const struct iphdr outer4_copy = *ip_hdr(skb);
	const struct icmphdr outer_icmp4_copy = *icmp_hdr(skb);
	struct frag_hdr inner_frag_copy;
	bool has_inner_frag, first_inner_frag, df;
	struct ipv6hdr inner6_copy;
	unsigned int inner_l3_off, inner_l4_off;
	__u8 inner_l4_proto;
	struct iphdr *inner4;
	__be32 saddr, daddr;
	int err;

	if (unlikely(!(cb->flags & IPXLAT_SKB_F_IN_ICMP_ERR)))
		return -EINVAL;

	inner_l3_off = cb->inner_l3_offset;
	inner_l4_off = cb->inner_l4_offset;
	if (unlikely(inner_l4_off < inner_l3_off))
		return -EINVAL;

	outer_prefix_len = inner_l3_off;
	inner6_copy = *(struct ipv6hdr *)(skb->data + outer_prefix_len);
	inner_l3_len = inner_l4_off - inner_l3_off;
	inner_l4_proto = nexthdr2proto(cb->inner_l4_proto);
	has_inner_frag = !!cb->inner_fragh_off;
	first_inner_frag = true;
	if (unlikely(has_inner_frag)) {
		inner_frag_copy = *(struct frag_hdr *)(skb->data +
						      cb->inner_fragh_off);
		first_inner_frag = is_first_frag6(&inner_frag_copy);
	}

	inner_l4_len = first_inner_frag ? ipxl_l4_min_len(inner_l4_proto) : 0;
	if (unlikely(first_inner_frag &&
		     skb_ensure_writable(skb, inner_l4_off + inner_l4_len)))
		return -ENOMEM;

	err = siit64_addrs(ctx->cfg, &inner6_copy, false, &saddr, &daddr);
	if (unlikely(err))
		return err;

	old_prefix = outer_prefix_len + inner_l3_len;
	new_prefix = outer_prefix_len + sizeof(struct iphdr);
	*inner_delta = (int)new_prefix - (int)old_prefix;

	skb_pull(skb, old_prefix);
	skb_push(skb, new_prefix);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	*ip_hdr(skb) = outer4_copy;
	*icmp_hdr(skb) = outer_icmp4_copy;

	inner4 = (struct iphdr *)(skb->data + outer_prefix_len);
	inner_tot_len = ntohs(inner6_copy.payload_len) + sizeof(inner6_copy) -
			inner_l3_len + sizeof(struct iphdr);
	inner4->version = 4;
	inner4->ihl = 5;
	inner4->tos = get_traffic_class(&inner6_copy);
	inner4->tot_len = cpu_to_be16(inner_tot_len);
	/* RFC7915 §5.1 */
	if (likely(!has_inner_frag)) {
		df = inner_tot_len > (IPV6_MIN_MTU - sizeof(struct iphdr));
		inner4->frag_off = build_v4_frag_offset(df, 0, 0);
	} else {
		inner4->frag_off =
			build_v4_frag_offset(0,
					     is_mf_set_ipv6(&inner_frag_copy),
					     get_v6_frag_offset(&inner_frag_copy));
	}
	inner4->ttl = inner6_copy.hop_limit;
	inner4->protocol = inner_l4_proto;
	inner4->saddr = saddr;
	inner4->daddr = daddr;

	if (likely(!has_inner_frag)) {
		inner4->id = 0;
		__ip_select_ident(dev_net(ctx->dev), inner4, 1);
	} else {
		inner4->id =
			cpu_to_be16(be32_to_cpu(inner_frag_copy.identification));
	}
	inner4->check = 0;
	inner4->check = ip_fast_csum(inner4, inner4->ihl);

	if (unlikely(!first_inner_frag))
		return 0;

	inner_l4_off = outer_prefix_len + sizeof(struct iphdr);
	return ipxl_inner_l4_64(skb, inner_l4_off, inner4, &inner6_copy);
}

static int
ipxl_icmp64_squeeze_extensions_inplace(struct sk_buff *skb,
				       unsigned int icmp6_ipl, int inner_delta,
				       enum ipxl_icmp_ie_policy ie_policy)
{
	struct icmphdr *ic4;
	unsigned int outer_hdrs_len, payload_len;
	unsigned int icmp4_iel_in, icmp4_iel_out;
	unsigned int out_pad, max_iel, pkt_len_cap;
	unsigned int icmp4_ipl_out_bytes, icmp4_ipl_out = 0;
	int icmp4_ipl_in_bytes, err;

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

	err = ipxl_icmp46_relayout(skb, outer_hdrs_len,
				   (unsigned int)icmp4_ipl_in_bytes,
				   icmp4_iel_in, icmp4_ipl_out_bytes, out_pad,
				   icmp4_iel_out);
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

static int ipxl_icmp6_to_icmp4_error(const struct ipxl_pkt_ctx *ctx,
				     struct sk_buff *skb,
				     const struct icmp6hdr *ic6)
{
	const struct ipxl_cb *cb = ipxl_skb_cb(skb);
	enum ipxl_icmp_ie_policy ie_policy;
	unsigned int icmp6_ipl;
	int inner_delta, err;
	struct icmphdr *ic4;

	if (unlikely(!(cb->flags & IPXLAT_SKB_F_IN_ICMP_ERR))) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return -EINVAL;
	}

	ic4 = (struct icmphdr *)(skb->data + skb_transport_offset(skb));
	err = ipxl_icmp6_errhdr_to_icmp4(ctx, skb, ic6, ic4, &ie_policy);
	if (unlikely(err))
		return err;

	err = ipxl_icmp_inner_6to4_xlate(ctx, skb, &inner_delta);
	if (unlikely(err))
		return err;

	icmp6_ipl = ic6->icmp6_datagram_len << 3;
	err = ipxl_icmp64_squeeze_extensions_inplace(skb, icmp6_ipl,
						     inner_delta, ie_policy);
	if (unlikely(err))
		return err;

	ipxl_compute_icmp4_csum(skb);
	return 0;
}

static int ipxl_icmp6_to_icmp4(const struct ipxl_pkt_ctx *ctx,
			       struct sk_buff *skb, bool is_err,
			       const struct icmp6hdr *ic6_copy,
			       const struct ipv6hdr *in6)
{
	if (unlikely(is_err)) {
		return ipxl_icmp6_to_icmp4_error(ctx, skb, ic6_copy);
	}

	return ipxl_icmp6_to_icmp4_info(skb, in6);
}

static __be16 ipxl_v6_to_v4_frag_off(struct sk_buff *skb,
				     const struct frag_hdr *frag6,
				     __u8 l4_proto)
{
	bool df;

	if (frag6)
		return build_v4_frag_offset(0, is_mf_set_ipv6(frag6),
					    get_v6_frag_offset(frag6));

	if (skb_has_frag_list(skb))
		return build_v4_frag_offset(false, 0, 0);

	if (skb_is_gso(skb)) {
		df = (l4_proto == IPPROTO_TCP) &&
		     (ipxl_skb_cb(skb)->payload_off +
			      skb_shinfo(skb)->gso_size >
		      (IPV6_MIN_MTU - sizeof(struct iphdr)));
		return build_v4_frag_offset(df, 0, 0);
	}

	return build_v4_frag_offset(skb->len > (IPV6_MIN_MTU -
						sizeof(struct iphdr)),
				    0, 0);
}

static int ipxl_v6_to_v4_inplace(const struct ipxl_pkt_ctx *ctx,
				 struct sk_buff *skb)
{
	bool has_frag, first_frag, is_icmp6_err;
	const struct ipv6hdr in6 = *ipv6_hdr(skb);
	struct ipxl_cb *cb = ipxl_skb_cb(skb);
	unsigned int ip6_len, min_l4_len;
	__u8 l4_proto, out_l4_proto;
	int l3_delta;
	struct frag_hdr frag_copy;
	struct icmp6hdr ic6_copy;
	struct frag_hdr *frag6;
	__be32 saddr, daddr;
	struct iphdr *iph4;
	int err;

	/* snapshot original outer IPv6 fields before L3 rewrite */
	ip6_len = cb->l4_off;
	l4_proto = cb->l4_proto;
	out_l4_proto = nexthdr2proto(l4_proto);
	frag6 = pkt_frag_hdr(skb);
	has_frag = !!frag6;
	if (unlikely(has_frag))
		frag_copy = *frag6;
	first_frag = is_first_frag6(has_frag ? &frag_copy : NULL);
	is_icmp6_err = cb->flags & IPXLAT_SKB_F_IN_ICMP_ERR;
	if (unlikely(is_icmp6_err)) {
		if (unlikely(l4_proto != NEXTHDR_ICMP))
			return -EINVAL;

		ic6_copy = *icmp6_hdr(skb);
	}

	/* derive translated IPv4 endpoints */
	err = siit64_addrs(ctx->cfg, &in6, is_icmp6_err, &saddr, &daddr);
	if (unlikely(err))
		return err;
	// log_debug("6->4 addrs: %pI6c->%pI6c => %pI4->%pI4",
	// 	  &in6.saddr, &in6.daddr, &saddr, &daddr);

	/* replace outer IPv6 hdr with IPv4 hdr in-place */
	l3_delta = (int)sizeof(struct iphdr) - (int)ip6_len;
	skb_pull_rcsum(skb, ip6_len);
	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	skb->protocol = htons(ETH_P_IP);

	/* rebase parser metadata after header-size delta */
	err = ipxl_cb_rebase_offsets(cb, l3_delta);
	if (unlikely(err))
		return err;

	cb->l3_hdr_len = sizeof(struct iphdr);
	cb->fragh_off = 0;
	cb->l4_proto = out_l4_proto;
	if (unlikely(!ipxl_cb_offsets_valid(cb))) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return -EINVAL;
	}

	/* build translated IPv4 outer header */
	iph4 = ip_hdr(skb);
	iph4->version = 4;
	iph4->ihl = 5;
	iph4->tos = get_traffic_class(&in6);
	iph4->tot_len = cpu_to_be16(skb->len);
	iph4->frag_off = ipxl_v6_to_v4_frag_off(skb,
						has_frag ? &frag_copy : NULL,
						out_l4_proto);
	iph4->ttl = in6.hop_limit - 1;
	iph4->protocol = out_l4_proto;
	iph4->saddr = saddr;
	iph4->daddr = daddr;

	if (has_frag)
		iph4->id = cpu_to_be16(be32_to_cpu(frag_copy.identification));
	else {
		iph4->id = 0;
		__ip_select_ident(dev_net(ctx->dev), iph4, 1);
	}
	iph4->check = 0;
	iph4->check = ip_fast_csum(iph4, iph4->ihl);

	if (unlikely(!first_frag))
		goto out;

	min_l4_len = ipxl_l4_min_len(out_l4_proto);
	if (unlikely(skb_ensure_writable(skb, skb_transport_offset(skb) +
						      min_l4_len)))
		return -ENOMEM;

	switch (out_l4_proto) {
	case IPPROTO_TCP:
		err = ipxl_tcp6_to_tcp4(skb, &in6, false);
		break;
	case IPPROTO_UDP:
		err = ipxl_udp6_to_udp4(skb, &in6, false);
		break;
	case IPPROTO_ICMP:
		err = ipxl_icmp6_to_icmp4(ctx, skb, is_icmp6_err, &ic6_copy,
					  &in6);
		break;
	default:
		err = 0;
		break;
	}
	if (unlikely(err)) {
		netdev_info(ctx->dev,
			    "4->6: l4 translation failed proto=%u err=%d\n",
			    l4_proto, err);
		return err;
	}

out:
	return ipxl_finalize_offload_64(skb, out_l4_proto,
					ip_is_fragment(iph4));
}

static int ipxl_tcp4_to_tcp6(struct sk_buff *skb, const struct iphdr *in4,
			     const struct ipv6hdr *iph6, struct tcphdr *tcp_new,
			     bool inner)
{
	struct tcphdr tcp_old;
	__sum16 csum16;

	/* For CHECKSUM_PARTIAL input, the checksum field is a seed for
	 * deferred completion (covering only the IPv4 pseudoheader), not a
	 * final checksum over header+payload. We can use hardware checksum
	 * offload to complete the checksum calculation.
	 *
	 * The strategy:
	 * 1. Convert IPv4 partial checksum to IPv6 partial checksum
	 *    (swap pseudoheaders)
	 * 2. Set up CHECKSUM_PARTIAL offload so NIC will:
	 *    - Start checksumming at transport header
	 *    - Add the partial pseudoheader checksum we pre-computed
	 *    - Compute checksum over transport header + payload
	 *    - Write final result to checksum field
	 *
	 * tcp_v6_check(len, saddr, daddr, csum):
	 *   Computes IPv6 pseudoheader checksum and folds it to 16 bits
	 *   Returns ~folded(IPv6_pseudoheader + csum)
	 *
	 *   We pass csum=0 because we don't have any pre-computed transport
	 *   data to add. The incoming IPv4 pseudoheader checksum is discarded
	 *   since addresses change.
	 *
	 *   tcp_v6_check will simply call csum_ipv6_magic which returns the
	 *   folded and complemented pseudoheader checksum. We store its
	 *   negation as the pseudoheader contribution seed expected by
	 *   CHECKSUM_PARTIAL completion. This is necessary because the final TCP
	 *   checksum formula is: checksum = ~(pseudoheader + tcp_hdr + payload)
	 *
	 *   With CHECKSUM_PARTIAL, the NIC/stack will:
	 *   1. Compute the sum of bytes from csum_start to end of packet
	 *      (= tcp_header + payload)
	 *   2. Add the value already in the checksum field (= pseudoheader_sum)
	 *   3. Complement and fold the result
	 *
	 *   So:
	 *   NIC computes: ~(existing_check_field + tcp_header + payload)
	 *               = ~(pseudoheader_sum + tcp_header + payload)
	 *               = correct final checksum!
	 *
	 *   If we stored the complemented value (tcp_v6_check() directly), the
	 *   NIC would compute a wrong checksum.
	 */
	/* TODO: outer fast path can avoid this mode branch entirely by splitting
	 * outer/inner wrappers and sharing only checksum primitives.
	 */
	if (!inner && skb->ip_summed == CHECKSUM_PARTIAL) {
		tcp_new->check = ~tcp_v6_check(skb_datagram_len(skb),
					       &iph6->saddr, &iph6->daddr, 0);
		/* setup and validate the csum */
		return ipxl_set_partial_csum(skb,
					     offsetof(struct tcphdr, check));
	}

	/* Current checksum covers: IPv4_pseudoheader + TCP_header + TCP_payload
	 * We need                : IPv6_pseudoheader + TCP_header + TCP_payload
	 *
	 * tcp_old is needed because update_csum_4to6() will subtract the old
	 * TCP header checksum contribution and add the new one. If we used
	 * tcp_new directly with its original checksum value, we'd be
	 * subtracting the checksum field itself twice (once implicitly as part
	 * of the header, and once explicitly), resulting in an incorrect
	 * calculation.
	 *
	 * By using tcp_old with check=0, we ensure the subtraction only
	 * removes the other TCP header fields (source/dest port, sequence
	 * number, etc.), not the checksum field itself.
	 */
	csum16 = tcp_new->check;
	tcp_old = *tcp_new;
	tcp_old.check = 0;
	tcp_new->check = 0;
	tcp_new->check = update_csum_4to6(csum16, in4, &tcp_old, iph6, tcp_new,
					  sizeof(*tcp_new));
	if (!inner)
		skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int ipxl_udp4_to_udp6(struct sk_buff *skb, const struct iphdr *in4,
			     const struct ipv6hdr *iph6, struct udphdr *udp_new,
			     unsigned int l4_off, unsigned int zero_csum_len,
			     bool inner)
{
	struct udphdr udp_old;
	__sum16 csum16;

	/* Outer path enforces UDP zero-checksum policy in validation.
	 * Inner quoted packets can carry a zero UDP checksum; keep it as-is.
	 */
	/* TODO: outer fast path can avoid this mode branch entirely by splitting
	 * outer/inner wrappers and sharing only checksum primitives.
	 */
	if (!inner && skb->ip_summed == CHECKSUM_PARTIAL &&
	    likely(udp_new->check != 0)) {
		udp_new->check = ~udp_v6_check(skb_datagram_len(skb),
					       &iph6->saddr, &iph6->daddr, 0);
		return ipxl_set_partial_csum(skb,
					     offsetof(struct udphdr, check));
	}

	/* incoming UDP IPv4 has no checksum (legal in IPv4, not in IPv6) */
	if (unlikely(udp_new->check == 0)) {
		/* we don't care about inner packets with 0 csum */
		if (inner)
			return 0;

		/* zero_csum_len is the L4 span (UDP header + UDP payload bytes)
		 * we use for checksum computation
		 */
		if (unlikely(!zero_csum_len))
			return -EINVAL;

		udp_new->check = ipxl_l4_csum_ipv6(&iph6->saddr, &iph6->daddr,
						   skb, l4_off, zero_csum_len,
						   IPPROTO_UDP);
		/* distinguish between a zero csum UDP packet and a real
		 * computed csum that folded to 0x0000
		 */
		if (udp_new->check == 0)
			udp_new->check = CSUM_MANGLED_0;
		if (!inner)
			skb->ip_summed = CHECKSUM_NONE;
		return 0;
	}

	csum16 = udp_new->check;
	udp_old = *udp_new;
	udp_old.check = 0;
	udp_new->check = 0;
	udp_new->check = update_csum_4to6(csum16, in4, &udp_old, iph6, udp_new,
					  sizeof(*udp_new));
	if (!inner)
		skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int ipxl_ensure_tailroom(struct sk_buff *skb, unsigned int grow)
{
	int err;

	if (!grow || skb_tailroom(skb) >= grow)
		return 0;

	err = pskb_expand_head(skb, 0, grow - skb_tailroom(skb), GFP_ATOMIC);
	if (unlikely(err))
		return err;

	return 0;
}

static int ipxl_icmp46_relayout(struct sk_buff *skb, unsigned int outer_len,
				unsigned int in_ipl, unsigned int in_iel,
				unsigned int out_ipl, unsigned int out_pad,
				unsigned int out_iel)
{
	const unsigned int new_len = outer_len + out_ipl + out_pad + out_iel;
	const unsigned int out_ie_off = outer_len + out_ipl + out_pad;
	const unsigned int in_ie_off = outer_len + in_ipl;
	const unsigned int old_len = skb->len;
	unsigned int grow = 0;
	int err;

	/* new_len > old_len here means "we need extra bytes on top of
	 * already-translated length", mainly due padding/layout decisions
	 * while keeping extensions
	 */
	if (unlikely(new_len > old_len)) {
		grow = new_len - old_len;

		err = ipxl_ensure_tailroom(skb, grow);
		if (unlikely(err))
			return err;

		__skb_put(skb, grow);
	}

	if (unlikely(out_iel))
		memmove(skb->data + out_ie_off, skb->data + in_ie_off, out_iel);

	if (unlikely(out_pad))
		memset(skb->data + outer_len + out_ipl, 0, out_pad);

	if (unlikely(new_len < old_len)) {
		err = pskb_trim(skb, new_len);
		if (unlikely(err))
			return err;
	}

	return 0;
}

static int ipxl_icmp46_squeeze_extensions(struct sk_buff *skb,
					  unsigned int icmp4_ipl,
					  int inner_delta,
					  enum ipxl_icmp_ie_policy ie_policy)
{
	unsigned int icmp6_iel_in, icmp6_iel_out, max_iel;
	unsigned int outer_hdrs_len, out_pad, payload_len;
	unsigned int icmp6_ipl_out_bytes, pkt_len_cap;
	unsigned int icmp6_ipl_out = 0;
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

	err = ipxl_icmp46_relayout(skb, outer_hdrs_len,
				   (unsigned int)icmp6_ipl_in_bytes,
				   icmp6_iel_in, icmp6_ipl_out_bytes, out_pad,
				   icmp6_iel_out);
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

static __be32 ipxl_icmp6_min_mtu(const struct ipxl_pkt_ctx *ctx,
				 unsigned int pkt_mtu, unsigned int nexthop6mtu,
				 unsigned int nexthop4mtu, __u16 tot_len_field)
{
	const __u16 *plateaus;
	__u32 result;
	__u16 count;
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
	 * RFC7915 §4.2 (ICMPv4 Frag Needed -> ICMPv6 Packet Too Big):
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

static int ipxl_icmp46_compute_mtu6(const struct ipxl_pkt_ctx *ctx,
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
		ipxl_icmp6_min_mtu(ctx, be16_to_cpu(in_icmp->un.frag.mtu),
				   out_mtu, in_mtu,
				   be16_to_cpu(inner4->tot_len));
	return 0;
}

static int ipxl_icmp46_dest_unreach(const struct ipxl_pkt_ctx *ctx,
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
		return ipxl_icmp46_compute_mtu6(ctx, skb, in, out, inner4);
	}

	return -EPROTONOSUPPORT;
}

static const __u8 ipxl_icmp46_ptrs[] = { 0,    1, 4,  4,    0xff, 0xff, 0xff,
					 0xff, 7, 6,  0xff, 0xff, 8,	8,
					 8,    8, 24, 24,   24,	  24 };

static int ipxl_icmp46_param_prob(const struct icmphdr *in,
				  struct icmp6hdr *out)
{
	__u8 ptr;

	if (unlikely(in->code != ICMP_PTR_INDICATES_ERR &&
		     in->code != ICMP_BAD_LENGTH))
		return -EPROTONOSUPPORT;

	ptr = be32_to_cpu(in->icmp4_unused) >> 24;
	if (unlikely(ptr >= ARRAY_SIZE(ipxl_icmp46_ptrs) ||
		     ipxl_icmp46_ptrs[ptr] == 0xff))
		return -EPROTONOSUPPORT;

	out->icmp6_pointer = cpu_to_be32(ipxl_icmp46_ptrs[ptr]);
	return 0;
}

static int ipxl_icmp4_to_icmp6_info_type_code(const struct icmphdr *in,
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

static int ipxl_icmp4_to_icmp6_info(struct sk_buff *skb,
				    const struct icmphdr *icmp4,
				    const struct ipv6hdr *ip6,
				    struct icmp6hdr *icmp6, unsigned int l4_off,
				    bool inner)
{
	struct icmp6hdr icmp6_zero;
	struct icmphdr icmp4_zero;
	__wsum csum;
	int err;

	err = ipxl_icmp4_to_icmp6_info_type_code(icmp4, icmp6);
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
					     skb->len - l4_off,
					     IPPROTO_ICMPV6, csum);

	/* on the outer header don't interpret csum metadata
	 * as offload/accumulator state anymore
	 */
	if (!inner)
		skb->ip_summed = CHECKSUM_NONE;

	return 0;
}

static int ipxl_icmp4_to_icmp6_type_code(const struct ipxl_pkt_ctx *ctx,
					 struct sk_buff *skb,
					 const struct icmphdr *in,
					 struct icmp6hdr *out,
					 const struct iphdr *inner4,
					 enum ipxl_icmp_ie_policy *ie_policy)
{
	int err;

	*ie_policy = IPXL_ICMP_IE_ALLOWED;

	switch (in->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		return ipxl_icmp4_to_icmp6_info_type_code(in, out);
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
		return ipxl_icmp46_dest_unreach(ctx, skb, in, out, inner4);
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
		err = ipxl_icmp46_param_prob(in, out);
		if (unlikely(err))
			return err;
		return 0;
	}

	return -EPROTONOSUPPORT;
}

static void ipxl_v4_to_v6_hdr(struct ipv6hdr *iph6, const struct iphdr *iph4,
			      unsigned int payload_len, __u8 nexthdr,
			      __u8 hop_limit)
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

static int ipxl_inner_l4_46(struct sk_buff *skb, unsigned int inner_l4_off,
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
		return ipxl_tcp4_to_tcp6(skb, inner4, inner6, tcp, true);
	case IPPROTO_UDP:
		udp = (struct udphdr *)(skb->data + inner_l4_off);
		return ipxl_udp4_to_udp6(skb, inner4, inner6, udp, inner_l4_off,
					 cb->inner_udp_zero_csum_len, true);
	case IPPROTO_ICMP:
		icmp4 = *(struct icmphdr *)(skb->data + inner_l4_off);
		icmp6 = (struct icmp6hdr *)(skb->data + inner_l4_off);
		return ipxl_icmp4_to_icmp6_info(skb, &icmp4, inner6, icmp6,
						inner_l4_off, true);
	default:
		return 0;
	}
}

static int ipxl_icmp_inner_4to6_xlate(const struct ipxl_pkt_ctx *ctx,
				      struct sk_buff *skb,
				      const struct iphdr *inner4)
{
	unsigned int inner_l4_off, inner_l3_payload, inner_l4_payload,
		old_prefix, new_prefix, inner_tot_len;
	const unsigned int outer_l3_len = skb_transport_offset(skb);
	const unsigned int inner_l3_len = inner4->ihl << 2;
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
	ipxl_v4_to_v6_hdr(inner_ip6, inner4, inner_l3_payload,
			  need_frag ? NEXTHDR_FRAGMENT :
				      ipxlat_proto2nexthdr(inner4->protocol),
			  inner4->ttl);
	siit46_addrs_skb(ctx->cfg, inner4, inner_ip6);

	if (unlikely(need_frag)) {
		fh6 = (struct frag_hdr *)(inner_ip6 + 1);
		ipxl_v6_frag_from_v4(fh6, inner4, inner4->protocol);
	}

	if (unlikely(inner4->frag_off & htons(IP_OFFSET)))
		return 0;

	inner_l4_off = outer_l3_len + sizeof(struct icmp6hdr) +
		       sizeof(struct ipv6hdr) +
		       (need_frag ? sizeof(struct frag_hdr) : 0);
	inner_l4_payload = inner_l4_off + ipxl_l4_min_len(inner4->protocol);
	if (unlikely(skb_ensure_writable(skb, inner_l4_payload)))
		return -ENOMEM;

	return ipxl_inner_l4_46(skb, inner_l4_off, inner4, inner_ip6);
}

static int ipxl_icmp4_to_icmp6_error(const struct ipxl_pkt_ctx *ctx,
				     struct sk_buff *skb)
{
	const struct ipxl_cb *cb = ipxl_skb_cb(skb);
	const struct icmphdr icmp4 = *icmp_hdr(skb);
	enum ipxl_icmp_ie_policy ie_policy;
	unsigned int inner4_off;
	struct iphdr inner4_ip;
	int inner_delta, err;

	if (unlikely(!(cb->flags & IPXLAT_SKB_F_IN_ICMP_ERR))) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return -EINVAL;
	}

	inner4_off = cb->inner_l3_offset;
	/* we can't make assumptions on the alignment of the inner header */
	memcpy(&inner4_ip, skb->data + inner4_off, sizeof(inner4_ip));

	/* translate the inner packet headers */
	err = ipxl_icmp_inner_4to6_xlate(ctx, skb, &inner4_ip);
	if (unlikely(err))
		return err;

	err = ipxl_icmp4_to_icmp6_type_code(ctx, skb, &icmp4, icmp6_hdr(skb),
					    &inner4_ip, &ie_policy);
	if (unlikely(err))
		return err;

	inner_delta = sizeof(struct ipv6hdr) +
		      (ip_is_fragment(&inner4_ip) * sizeof(struct frag_hdr)) -
		      (inner4_ip.ihl << 2);
	err = ipxl_icmp46_squeeze_extensions(skb,
					     icmp4.icmp4_datagram_length << 2,
					     inner_delta, ie_policy);
	if (unlikely(err))
		return err;

	icmp6_hdr(skb)->icmp6_cksum = 0;
	icmp6_hdr(skb)->icmp6_cksum = ipxl_icmp6_csum(ipv6_hdr(skb), skb);
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int ipxl_icmp4_to_icmp6(const struct ipxl_pkt_ctx *ctx,
			       struct sk_buff *skb)
{
	const struct icmphdr icmp4 = *icmp_hdr(skb);

	if (unlikely(ipxl_skb_cb(skb)->flags & IPXLAT_SKB_F_IN_ICMP_ERR))
		return ipxl_icmp4_to_icmp6_error(ctx, skb);

	return ipxl_icmp4_to_icmp6_info(skb, &icmp4, ipv6_hdr(skb),
					icmp6_hdr(skb),
					skb_transport_offset(skb), false);
}

static unsigned int ipxl_v4_to_v6_pmtu(const struct ipxl_pkt_ctx *ctx,
				       const struct sk_buff *skb,
				       const struct iphdr *in4)
{
	struct flowi6 fl6 = {};
	struct dst_entry *dst;
	unsigned int mtu6;

	siit46_addr(&ctx->cfg->pool6, in4->saddr, &fl6.saddr);
	siit46_addr(&ctx->cfg->pool6, in4->daddr, &fl6.daddr);
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

/* check if the incoming IPv4 packet needs pre-fragmentation to be translated
 * and forwarded as a set of IPv6 packets */
static int ipxl_v4_prefrag_plan(const struct ipxl_pkt_ctx *ctx,
				struct sk_buff *skb)
{
	unsigned int pmtu6, threshold6, pkt_len6, pkt_len4, frag_max_size;
	struct ipxl_cb *cb = ipxl_skb_cb(skb);
	const struct iphdr *in4 = ip_hdr(skb);
	unsigned int old_l3_len, new_l3_len;
	int frag_l3_delta, l3_delta;

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
	pmtu6 = ipxl_v4_to_v6_pmtu(ctx, skb, in4);
	/* DF packets are never locally pre-fragmented */
	if (likely(is_df_set(in4))) {
		/* If we're not allowed to fragment but translation would
		 * exceed the next-hop MTU on the IPv6 side, emit ICMPv4
		 * FRAG_NEEDED.
		 * Incoming ICMPv4 errors are exempt: they proceed to the
		 * ICMP error squeeze/trim path.
		 */
		if (unlikely(pkt_len6 > pmtu6 &&
			     !(cb->flags & IPXLAT_SKB_F_IN_ICMP_ERR)))
			return ipxl_drop_icmp(ctx, skb, ICMP_DEST_UNREACH,
					      ICMP_FRAG_NEEDED,
					      pmtu6 > 20 ? pmtu6 - 20 : 0);

		return 0;
	}

	threshold6 = min(pmtu6, ctx->cfg->lowest_ipv6_mtu);
	if (likely(pkt_len6 <= threshold6))
		return 0;

	frag_l3_delta =
		(int)(sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)) -
		(int)old_l3_len;
	frag_max_size = threshold6 - frag_l3_delta;
	cb->frag_max_size = min_t(unsigned int, frag_max_size, IP_MAX_MTU);
	return 0;
}

static int ipxl_v4_to_v6_inplace(const struct ipxl_pkt_ctx *ctx,
				 struct sk_buff *skb)
{
	unsigned int ip4_len, ip6_len, min_l4_len;
	struct ipxl_cb *cb = ipxl_skb_cb(skb);
	const struct iphdr in4 = *ip_hdr(skb);
	bool first_frag, need_frag;
	struct frag_hdr *fh6;
	struct ipv6hdr *iph6;
	int delta, err;
	__u8 l4_proto;

	/* snapshot the original IPv4 header fields before skb layout changes */
	ip4_len = in4.ihl << 2;
	l4_proto = cb->l4_proto;
	first_frag = !(in4.frag_off & htons(IP_OFFSET));
	need_frag = ip_is_fragment(&in4);

	/* compute v4->v6 hdr delta and ensure writable headroom in-place */
	ip6_len = sizeof(struct ipv6hdr) +
		  (need_frag ? sizeof(struct frag_hdr) : 0);
	delta = (int)ip6_len - (int)ip4_len;

	/* make room for the new hdrs */
	if (unlikely(skb_cow_head(skb, max_t(int, 0, delta))))
		return -ENOMEM;

	/* replace outer L3 area: drop IPv4 hdr, reserve IPv6(+Frag) hdr */
	skb_pull_rcsum(skb, ip4_len);
	skb_push(skb, ip6_len);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, ip6_len);
	skb->protocol = htons(ETH_P_IPV6);

	/* build outer IPv6 base hdr from translated IPv4 fields */
	iph6 = ipv6_hdr(skb);
	ipxl_v4_to_v6_hdr(iph6, &in4, skb->len - sizeof(*iph6),
			  ipxlat_proto2nexthdr(l4_proto), in4.ttl - 1);

	/* translate IPv4 endpoints into IPv6 addresses using pool6 prefix */
	siit46_addrs_skb(ctx->cfg, &in4, iph6);
	// log_debug("4->6 addrs: %pI4->%pI4 => %pI6c->%pI6c",
	// 	  &in4.saddr, &in4.daddr, &iph6->saddr, &iph6->daddr);

	/* add IPv6 fragment hdr when the IPv4 packet carried fragmentation */
	if (unlikely(need_frag)) {
		iph6->nexthdr = NEXTHDR_FRAGMENT;

		fh6 = (struct frag_hdr *)(iph6 + 1);
		ipxl_v6_frag_from_v4(fh6, &in4, l4_proto);
		cb->fragh_off = sizeof(struct ipv6hdr);
	}

	/* Rebase cached offset and protocol metadata after hdr size delta.
	 * Note that the resulting payload offset must not be negative but
	 * that's not a problem currently given that cb->payload_off is
	 * initialized as l3_off + ip4_len (+ l4_len).
	 */
	err = ipxl_cb_rebase_offsets(cb, delta);
	if (unlikely(err))
		return err;

	cb->l3_hdr_len = ip6_len;
	cb->l4_proto = ipxlat_proto2nexthdr(l4_proto);
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
		err = ipxl_tcp4_to_tcp6(skb, &in4, iph6, tcp_hdr(skb), false);
		break;
	case IPPROTO_UDP:
		err = ipxl_udp4_to_udp6(skb, &in4, iph6, udp_hdr(skb),
					skb_transport_offset(skb),
					cb->udp_zero_csum_len, false);
		break;
	case IPPROTO_ICMP:
		err = ipxl_icmp4_to_icmp6(ctx, skb);
		break;
	default:
		err = 0;
		break;
	}
	if (unlikely(err))
		return err;

out:
	/* normalize checksum/offload metadata for the translated frame */
	return ipxl_finalize_offload_46(skb, l4_proto, need_frag);
}

static enum ipxl_xlat_action ipxl_xlat_64(const struct ipxl_pkt_ctx *ctx,
					  struct sk_buff *skb)
{
	if (ipxl_v6_validate(ctx, skb) ||
	    unlikely(ipxl_v6_to_v4_inplace(ctx, skb)))
		return ipxl_failed_action(skb);

	return IPXL_XLAT_ACT_FWD;
}

static enum ipxl_xlat_action ipxl_xlat_46(const struct ipxl_pkt_ctx *ctx,
					  struct sk_buff *skb)
{
	if (ipxl_v4_validate(ctx, skb))
		return ipxl_failed_action(skb);

	if (unlikely(ipxl_v4_prefrag_plan(ctx, skb)))
		return ipxl_failed_action(skb);
	if (unlikely(ipxl_skb_cb(skb)->frag_max_size))
		return IPXL_XLAT_ACT_PRE_FRAG;

	if (unlikely(ipxl_v4_to_v6_inplace(ctx, skb)))
		return ipxl_failed_action(skb);

	return IPXL_XLAT_ACT_FWD;
}

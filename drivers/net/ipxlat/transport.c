// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include <linux/icmp.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "transport.h"

int ipxl_set_partial_csum(struct sk_buff *skb, u16 csum_offset)
{
	if (likely(skb_partial_csum_set(skb, skb_transport_offset(skb),
					csum_offset)))
		return 0;
	return -EINVAL;
}

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

static __wsum pseudohdr6_csum(const struct ipv6hdr *hdr)
{
	return ~csum_unfold(csum_ipv6_magic(&hdr->saddr, &hdr->daddr, 0, 0, 0));
}

static __wsum pseudohdr4_csum(const struct iphdr *hdr)
{
	return csum_tcpudp_nofold(hdr->saddr, hdr->daddr, 0, 0, 0);
}

static __sum16 update_csum_6to4(__sum16 csum16, const struct ipv6hdr *in_ip6,
				const void *in_l4_hdr, size_t in_l4_hdr_len,
				const struct iphdr *out_ip4,
				const void *out_l4_hdr, size_t out_l4_hdr_len)
{
	__wsum csum;

	csum = ~csum_unfold(csum16);

	/*
	 * Regarding the pseudoheaders:
	 * The length is pretty hard to obtain if there's TCP and fragmentation,
	 * and whatever it is, it's not going to change. Therefore, instead of
	 * computing it only to cancel it out with itself later, simply sum
	 * (and subtract) zero.
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

unsigned int ipxl_l4_min_len(u8 protocol)
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

int ipxl_cb_rebase_offsets(struct ipxl_cb *cb, int delta)
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

	if (unlikely(cb->in_icmp_err)) {
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

bool ipxl_cb_offsets_valid(const struct ipxl_cb *cb)
{
	if (unlikely(cb->payload_off < cb->l4_off))
		return false;

	if (unlikely(cb->in_icmp_err)) {
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

__sum16 ipxl_l4_csum_ipv6(const struct in6_addr *saddr,
			  const struct in6_addr *daddr,
			  const struct sk_buff *skb,
			  unsigned int l4_off, unsigned int l4_len, u8 proto)
{
	return csum_ipv6_magic(saddr, daddr, l4_len, proto,
			       skb_checksum(skb, l4_off, l4_len, 0));
}

__sum16 ipxl_icmp6_csum(const struct ipv6hdr *iph6,
			const struct sk_buff *skb)
{
	unsigned int len;

	len = ipxl_skb_datagram_len(skb);
	return ipxl_l4_csum_ipv6(&iph6->saddr, &iph6->daddr, skb,
				 skb_transport_offset(skb), len,
				 IPPROTO_ICMPV6);
}

int ipxl_46_offload_finalize(struct sk_buff *skb, u8 l4_proto, bool is_fragment)
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

int ipxl_64_offload_finalize(struct sk_buff *skb, u8 l4_proto, bool is_fragment)
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

int ipxl_64_tcp(struct sk_buff *skb, const struct ipv6hdr *in6, bool inner)
{
	struct tcphdr tcp_old, *tcp_new;
	__sum16 csum16;

	tcp_new = tcp_hdr(skb);
	csum16 = tcp_new->check;
	tcp_old = *tcp_new;
	tcp_old.check = 0;

	if (!inner && skb->ip_summed == CHECKSUM_PARTIAL) {
		tcp_new->check = ~tcp_v4_check(ipxl_skb_datagram_len(skb),
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

int ipxl_64_inner_tcp(struct sk_buff *skb, const struct ipv6hdr *in6,
		      const struct iphdr *out4, struct tcphdr *tcp_new)
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

int ipxl_64_udp(struct sk_buff *skb, const struct ipv6hdr *in6, bool inner)
{
	struct udphdr udp_old, *udp_new;
	__sum16 csum16;

	udp_new = udp_hdr(skb);
	csum16 = udp_new->check;
	udp_old = *udp_new;
	udp_old.check = 0;

	if (!inner && skb->ip_summed == CHECKSUM_PARTIAL) {
		udp_new->check = ~udp_v4_check(ipxl_skb_datagram_len(skb),
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

int ipxl_64_inner_udp(struct sk_buff *skb, const struct ipv6hdr *in6,
		      const struct iphdr *out4, struct udphdr *udp_new)
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

int ipxl_46_tcp(struct sk_buff *skb, const struct iphdr *in4,
		const struct ipv6hdr *iph6, struct tcphdr *tcp_new, bool inner)
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
		tcp_new->check = ~tcp_v6_check(ipxl_skb_datagram_len(skb),
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

int ipxl_46_udp(struct sk_buff *skb, const struct iphdr *in4,
		const struct ipv6hdr *iph6, struct udphdr *udp_new,
		unsigned int l4_off, unsigned int zero_csum_len, bool inner)
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
		udp_new->check = ~udp_v6_check(ipxl_skb_datagram_len(skb),
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

static int ipxl_ensure_tailroom(struct sk_buff *skb, const unsigned int grow)
{
	int err;

	if (!grow || skb_tailroom(skb) >= grow)
		return 0;

	err = pskb_expand_head(skb, 0, grow - skb_tailroom(skb), GFP_ATOMIC);
	if (unlikely(err))
		return err;

	return 0;
}

int ipxl_icmp_relayout(struct sk_buff *skb, unsigned int outer_len,
		       unsigned int in_ipl, unsigned int in_iel,
		       unsigned int out_ipl, unsigned int out_pad,
		       unsigned int out_iel)
{
	const unsigned int new_len = outer_len + out_ipl + out_pad + out_iel,
			   out_ie_off = outer_len + out_ipl + out_pad,
			   in_ie_off = outer_len + in_ipl, old_len = skb->len;
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

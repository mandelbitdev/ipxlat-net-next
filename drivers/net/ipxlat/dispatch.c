// SPDX-License-Identifier: GPL-2.0
/*  IPXLAT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2026- Mandelbit, SRL
 *
 *  Author:	Alberto Leiva Popper <ydahhrk@gmail.com>
 *		Antonio Quartulli <antonio@mandelbit.com>
 *		Ralf Lici <ralf@mandelbit.com>
 */

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/ipv6.h>

#include "dispatch.h"
#include "address.h"
#include "packet.h"
#include "translate_46.h"
#include "translate_64.h"

static enum ipxl_action ipxl_resolve_failed_action(const struct sk_buff *skb)
{
	return ipxl_skb_cb(skb)->emit_icmp_err ? IPXL_ACT_ICMP_ERR :
						 IPXL_ACT_DROP;
}

enum ipxl_action ipxl_translate(struct ipxl_priv *ipxl, struct sk_buff *skb)
{
	const u16 proto = ntohs(skb->protocol);

	memset(skb->cb, 0, sizeof(struct ipxl_cb));

	if (proto == ETH_P_IPV6) {
		if (unlikely(ipxl_v6_validate_skb(skb)) ||
		    unlikely(ipxl_64_translate(ipxl, skb)))
			return ipxl_resolve_failed_action(skb);

		return IPXL_ACT_FWD;
	} else if (likely(proto == ETH_P_IP)) {
		if (unlikely(ipxl_v4_validate_skb(ipxl, skb)))
			return ipxl_resolve_failed_action(skb);

		if (unlikely(ipxl_46_translate(ipxl, skb)))
			return ipxl_resolve_failed_action(skb);

		return IPXL_ACT_FWD;
	}

	return IPXL_ACT_DROP;
}

/* mark current skb as drop-with-icmp and cache type/code/info for dispatch */
void ipxl_mark_icmp_drop(struct sk_buff *skb, u8 type, u8 code, u32 info)
{
	struct ipxl_cb *cb = ipxl_skb_cb(skb);

	cb->emit_icmp_err = true;
	cb->icmp_err.type = type;
	cb->icmp_err.code = code;
	cb->icmp_err.info = info;
}

static void ipxl_46_emit_icmp_err(struct ipxl_priv *ipxl, struct sk_buff *inner)
{
	const struct iphdr *iph = ip_hdr(inner);
	struct ipxl_cb *cb = ipxl_skb_cb(inner);

	struct inet_skb_parm param = {};

	/* build route metadata on demand when the packet has no dst */
	if (unlikely(!skb_dst(inner))) {
		const int reason =
			ip_route_input_noref(inner, iph->daddr, iph->saddr,
					     ip4h_dscp(iph), inner->dev);

		if (unlikely(reason)) {
			netdev_dbg(ipxl->dev,
				   "icmp4 emit: route build failed reason=%d\n",
				   reason);
			return;
		}
	}

	/* emit the ICMPv4 error */
	__icmp_send(inner, cb->icmp_err.type, cb->icmp_err.code,
		    htonl(cb->icmp_err.info), &param);
}

static void ipxl_64_emit_icmp_err(struct ipxl_priv *ipxl, struct sk_buff *inner)
{
	struct ipxl_cb *cb = ipxl_skb_cb(inner);
	struct ipv6_prefix pool6;

	struct inet6_skb_parm param = {};
	struct in6_addr pool6791v6;
	struct in6_addr saddr;

	/* prefer configured pool6791v6 as ICMPv6 source but if unset (::),
	 * derive the source by translating pool6791v4 through pool6.
	 */
	pool6791v6 = ipxl->cfg.pool6791v6;
	if (likely(!ipv6_addr_any(&pool6791v6))) {
		saddr = pool6791v6;
	} else {
		pool6 = ipxl->cfg.pool6;
		ipxl_46_convert_addr(&pool6,
				     READ_ONCE(ipxl->cfg.pool6791v4.s_addr),
				     &saddr);
	}

	/* emit the ICMPv6 error */
	icmp6_send(inner, cb->icmp_err.type, cb->icmp_err.code,
		   cb->icmp_err.info, &saddr, &param);
}

/* emit translator-generated ICMP errors for packets rejected by RFC rules */
void ipxl_emit_icmp_error(struct ipxl_priv *ipxl, struct sk_buff *inner)
{
	switch (ntohs(inner->protocol)) {
	case ETH_P_IPV6:
		ipxl_64_emit_icmp_err(ipxl, inner);
		return;
	case ETH_P_IP:
		ipxl_46_emit_icmp_err(ipxl, inner);
		return;
	default:
		DEBUG_NET_WARN_ON_ONCE(1);
		return;
	}
}

static void ipxl_forward_pkt(struct ipxl_priv *ipxl, struct sk_buff *skb)
{
	const unsigned int len = skb->len;
	int err;

	/* reinject as a fresh packet with scrubbed metadata */
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, false);

	err = gro_cells_receive(&ipxl->gro_cells, skb);
	if (likely(err == NET_RX_SUCCESS))
		dev_dstats_rx_add(ipxl->dev, len);
	/* on failure gro_cells updates rx drop stats internally */
}

int ipxl_process_skb(struct ipxl_priv *ipxl, struct sk_buff *skb,
		     bool allow_pre_frag)
{
	enum ipxl_action action;
	int err = -EINVAL;

	(void)allow_pre_frag;

	action = ipxl_translate(ipxl, skb);
	switch (action) {
	case IPXL_ACT_FWD:
		dev_dstats_tx_add(ipxl->dev, skb->len);
		ipxl_forward_pkt(ipxl, skb);
		return 0;
	case IPXL_ACT_ICMP_ERR:
		dev_dstats_tx_dropped(ipxl->dev);
		ipxl_emit_icmp_error(ipxl, skb);
		consume_skb(skb);
		return 0;
	case IPXL_ACT_DROP:
		goto drop_free;
	default:
		DEBUG_NET_WARN_ON_ONCE(1);
		goto drop_free;
	}

drop_free:
	dev_dstats_tx_dropped(ipxl->dev);
	kfree_skb(skb);
	return err;
}

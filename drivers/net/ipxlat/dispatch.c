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

#include <net/ip.h>

#include "dispatch.h"
#include "packet.h"
#include "translate_46.h"
#include "translate_64.h"

static enum ipxl_action ipxl_resolve_failed_action(const struct sk_buff *skb)
{
	return IPXL_ACT_DROP;
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

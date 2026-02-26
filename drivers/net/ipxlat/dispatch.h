/* SPDX-License-Identifier: GPL-2.0 */
/*  IPXLAT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2026- Mandelbit, SRL
 *
 *  Author:	Alberto Leiva Popper <ydahhrk@gmail.com>
 *		Antonio Quartulli <antonio@mandelbit.com>
 *		Ralf Lici <ralf@mandelbit.com>
 */

#ifndef _NET_IPXLAT_DISPATCH_H_
#define _NET_IPXLAT_DISPATCH_H_

#include "ipxlpriv.h"

struct sk_buff;

/**
 * enum ipxl_action - result of packet translation dispatch
 * @IPXL_ACT_DROP: drop the packet
 * @IPXL_ACT_FWD: packet translated and ready for forward reinjection
 * @IPXL_ACT_PRE_FRAG: packet must be fragmented before 4->6 translation
 * @IPXL_ACT_ICMP_ERR: drop packet and emit translator-generated ICMP error
 */
enum ipxl_action {
	IPXL_ACT_DROP,
	IPXL_ACT_FWD,
	IPXL_ACT_PRE_FRAG,
	IPXL_ACT_ICMP_ERR,
};

/**
 * ipxl_mark_icmp_drop - cache translator-generated ICMP action in skb cb
 * @skb: packet being rejected
 * @type: ICMP type to emit
 * @code: ICMP code to emit
 * @info: ICMP auxiliary info (pointer/MTU), host-endian
 *
 * This does not emit immediately; dispatch consumes the mark later and sends
 * the ICMP error through the appropriate address family path.
 */
void ipxl_mark_icmp_drop(struct sk_buff *skb, u8 type, u8 code, u32 info);

/**
 * ipxl_emit_icmp_error - emit cached translator-generated ICMP error
 * @ipxl: translator private context
 * @inner: offending packet used as quoted payload
 */
void ipxl_emit_icmp_error(struct ipxl_priv *ipxl, struct sk_buff *inner);

/**
 * ipxl_translate - validate/translate one packet and return next action
 * @ipxl: translator private context
 * @skb: packet to process
 *
 * Return: one of &enum ipxl_action.
 */
enum ipxl_action ipxl_translate(struct ipxl_priv *ipxl, struct sk_buff *skb);

/**
 * ipxl_process_skb - top-level packet handler for ndo_start_xmit/reinjection
 * @ipxl: translator private context
 * @skb: packet to process
 * @allow_pre_frag: allow 4->6 pre-fragment action for this invocation
 *
 * The function always consumes @skb directly or through fragmentation
 * callback/reinjection paths.
 *
 * Return: 0 on success, negative errno on processing failure.
 */
int ipxl_process_skb(struct ipxl_priv *ipxl, struct sk_buff *skb,
		     bool allow_pre_frag);

#endif /* _NET_IPXLAT_DISPATCH_H_ */

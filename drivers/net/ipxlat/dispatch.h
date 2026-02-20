/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_DISPATCH_H_
#define _NET_IPXLAT_DISPATCH_H_

#include "ipxlpriv.h"

struct sk_buff;

void ipxl_mark_icmp_drop(struct sk_buff *skb, u8 type, u8 code, u32 info);
int ipxl_emit_icmp_error(const struct ipxl_pkt_ctx *ctx, struct sk_buff *inner);

enum ipxl_action ipxl_translate(const struct ipxl_pkt_ctx *ctx,
				struct sk_buff *skb);

int ipxl_process_skb(struct ipxl_priv *ipxl, struct sk_buff *skb,
		     bool allow_pre_frag);

#endif /* _NET_IPXLAT_DISPATCH_H_ */

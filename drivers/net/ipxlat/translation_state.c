// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include "translation_state.h"

int ipxl_drop_icmp(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb,
		   __u8 type, __u8 code, __u32 info)
{
	struct ipxl_cb *cb;

	(void)ctx;

	if (skb) {
		cb = ipxl_skb_cb(skb);
		cb->flags |= IPXLAT_SKB_F_ICMP_ERR;
		cb->icmp_err.type = type;
		cb->icmp_err.code = code;
		cb->icmp_err.info = info;
	}

	return -EINVAL;
}

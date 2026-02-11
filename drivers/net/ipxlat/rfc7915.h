// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef MOD_XLAT_RFC7915_H_
#define MOD_XLAT_RFC7915_H_

struct ipxl_pkt_ctx;
struct sk_buff;

enum ipxl_xlat_action ipxl_xlat(const struct ipxl_pkt_ctx *ctx,
				struct sk_buff *skb);
int ipxl_emit_icmp_error(const struct ipxl_pkt_ctx *ctx, struct sk_buff *inner);

#endif /* MOD_XLAT_RFC7915_H_ */

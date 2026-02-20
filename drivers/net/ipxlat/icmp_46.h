/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_ICMP_46_H_
#define _NET_IPXLAT_ICMP_46_H_

#include "ipxlpriv.h"

struct sk_buff;

int ipxl_46_icmp(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb);

#endif /* _NET_IPXLAT_ICMP_46_H_ */

/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_ICMP_64_H_
#define _NET_IPXLAT_ICMP_64_H_

#include "ipxlpriv.h"

#define IPXL_ICMP4_ERROR_MAX_LEN 576U

struct icmp6hdr;
struct ipv6hdr;
struct sk_buff;

int ipxl_64_icmp(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb,
		 bool is_err, const struct icmp6hdr *ic6_copy,
		 const struct ipv6hdr *in6);

#endif /* _NET_IPXLAT_ICMP_64_H_ */

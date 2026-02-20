// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include "address.h"

static inline bool prefix6_contains(const struct ipv6_prefix *prefix,
				    const struct in6_addr *addr)
{
	return ipv6_prefix_equal(&prefix->addr, addr, prefix->len);
}

static __be32 addr64(const struct in6_addr *src, unsigned int q1,
		     unsigned int q2, unsigned int q3, unsigned int q4)
{
	q1 = src->s6_addr[q1];
	q2 = src->s6_addr[q2];
	q3 = src->s6_addr[q3];
	q4 = src->s6_addr[q4];
	return htonl((q1 << 24) | (q2 << 16) | (q3 << 8) | q4);
}

static void addr46(__be32 __src, struct in6_addr *dst, unsigned int q1,
		   unsigned int q2, unsigned int q3, unsigned int q4)
{
	u32 src = ntohl(__src);

	dst->s6_addr[q1] = ((src >> 24) & 0xFF);
	dst->s6_addr[q2] = ((src >> 16) & 0xFF);
	dst->s6_addr[q3] = ((src >> 8) & 0xFF);
	dst->s6_addr[q4] = ((src) & 0xFF);
}

void ipxl_addr_46(const struct ipv6_prefix *pool6, __be32 addr4,
		  struct in6_addr *addr6)
{
	*addr6 = pool6->addr;

	switch (pool6->len) {
	case 96:
		addr6->s6_addr32[3] = addr4;
		return;
	case 64:
		addr46(addr4, addr6, 9, 10, 11, 12);
		return;
	case 56:
		addr46(addr4, addr6, 7, 9, 10, 11);
		return;
	case 48:
		addr46(addr4, addr6, 6, 7, 9, 10);
		return;
	case 40:
		addr46(addr4, addr6, 5, 6, 7, 9);
		return;
	case 32:
		addr6->s6_addr32[1] = addr4;
		return;
	}

	DEBUG_NET_WARN_ON_ONCE(1);
}

int ipxl_addrs_64(const struct ipxl_cfg *cfg, const struct ipv6hdr *hdr6,
		  bool icmp_err, __be32 *src, __be32 *dst)
{
	const struct ipv6_prefix *pool6 = &cfg->pool6;
	const bool src_ok = prefix6_contains(pool6, &hdr6->saddr);

	if (unlikely(!src_ok && !icmp_err)) {
		pr_debug("ipxlat: %pI6c/%u does not contain %pI6c.\n",
			 &pool6->addr, pool6->len, &hdr6->saddr);
		return -EINVAL;
	}
	if (unlikely(!prefix6_contains(pool6, &hdr6->daddr))) {
		pr_debug("ipxlat: %pI6c/%u does not contain %pI6c.\n",
			 &pool6->addr, pool6->len, &hdr6->daddr);
		return -EINVAL;
	}

	switch (pool6->len) {
	case 96:
		if (likely(src_ok))
			*src = hdr6->saddr.s6_addr32[3];
		*dst = hdr6->daddr.s6_addr32[3];
		break;
	case 64:
		if (likely(src_ok))
			*src = addr64(&hdr6->saddr, 9, 10, 11, 12);
		*dst = addr64(&hdr6->daddr, 9, 10, 11, 12);
		break;
	case 56:
		if (likely(src_ok))
			*src = addr64(&hdr6->saddr, 7, 9, 10, 11);
		*dst = addr64(&hdr6->daddr, 7, 9, 10, 11);
		break;
	case 48:
		if (likely(src_ok))
			*src = addr64(&hdr6->saddr, 6, 7, 9, 10);
		*dst = addr64(&hdr6->daddr, 6, 7, 9, 10);
		break;
	case 40:
		if (likely(src_ok))
			*src = addr64(&hdr6->saddr, 5, 6, 7, 9);
		*dst = addr64(&hdr6->daddr, 5, 6, 7, 9);
		break;
	case 32:
		if (likely(src_ok))
			*src = hdr6->saddr.s6_addr32[1];
		*dst = hdr6->daddr.s6_addr32[1];
		break;
	default:
		DEBUG_NET_WARN_ON_ONCE(1);
		return -EINVAL;
	}

	if (unlikely(!src_ok))
		*src = cfg->pool6791v4.s_addr;

	return 0;
}

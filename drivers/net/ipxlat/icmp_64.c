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

#include <linux/icmpv6.h>

#include "icmp.h"
#include "packet.h"
#include "transport.h"

static int ipxl_64_map_icmp_info_type_code(const struct icmp6hdr *in,
					   struct icmphdr *out)
{
	switch (in->icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		out->type = ICMP_ECHO;
		out->code = 0;
		out->un.echo.id = in->icmp6_identifier;
		out->un.echo.sequence = in->icmp6_sequence;
		return 0;
	case ICMPV6_ECHO_REPLY:
		out->type = ICMP_ECHOREPLY;
		out->code = 0;
		out->un.echo.id = in->icmp6_identifier;
		out->un.echo.sequence = in->icmp6_sequence;
		return 0;
	default:
		return -EINVAL;
	}
}

static __sum16 ipxl_64_compute_icmp_info_csum(const struct ipv6hdr *in6,
					      const struct icmp6hdr *in_icmp6,
					      const struct icmphdr *out_icmp4,
					      unsigned int l4_len)
{
	struct icmp6hdr icmp6_zero;
	struct icmphdr icmp4_zero;
	__wsum csum, tmp;

	icmp6_zero = *in_icmp6;
	icmp6_zero.icmp6_cksum = 0;
	icmp4_zero = *out_icmp4;
	icmp4_zero.checksum = 0;

	csum = ~csum_unfold(in_icmp6->icmp6_cksum);
	tmp = ~csum_unfold(csum_ipv6_magic(&in6->saddr, &in6->daddr, l4_len,
					   NEXTHDR_ICMP, 0));
	csum = csum_sub(csum, tmp);
	csum = csum_sub(csum, csum_partial(&icmp6_zero, sizeof(icmp6_zero), 0));
	csum = csum_add(csum, csum_partial(&icmp4_zero, sizeof(icmp4_zero), 0));
	return csum_fold(csum);
}

static int ipxl_64_icmp_info(struct sk_buff *skb, const struct ipv6hdr *in6)
{
	struct icmp6hdr ic6_copy, *ic6;
	struct icmphdr *ic4;
	int err;

	ic6 = icmp6_hdr(skb);
	ic6_copy = *ic6;

	ic4 = (struct icmphdr *)(skb->data + skb_transport_offset(skb));
	err = ipxl_64_map_icmp_info_type_code(&ic6_copy, ic4);
	if (unlikely(err))
		return err;

	ic4->checksum = ipxl_64_compute_icmp_info_csum(in6, &ic6_copy, ic4,
						       ipxl_skb_datagram_len(skb));
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

int ipxl_64_icmp(struct ipxl_priv *ipxl, struct sk_buff *skb,
		 const struct ipv6hdr *in6)
{
	if (unlikely(ipxl_skb_cb(skb)->is_icmp_err))
		return -EPROTONOSUPPORT;

	return ipxl_64_icmp_info(skb, in6);
}

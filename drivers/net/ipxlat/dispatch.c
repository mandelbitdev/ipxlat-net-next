// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/inetdevice.h>
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

enum ipxl_action ipxl_translate(const struct ipxl_pkt_ctx *ctx,
				struct sk_buff *skb)
{
	const u16 proto = ntohs(skb->protocol);

	memset(skb->cb, 0, sizeof(struct ipxl_cb));

	if (proto == ETH_P_IPV6) {
		if (ipxl_v6_skb_validate(ctx, skb) ||
		    unlikely(ipxl_64_translate(ctx, skb)))
			return ipxl_resolve_failed_action(skb);

		return IPXL_ACT_FWD;
	} else if (likely(proto == ETH_P_IP)) {
		if (ipxl_v4_skb_validate(ctx, skb))
			return ipxl_resolve_failed_action(skb);

		if (unlikely(ipxl_46_prefrag_plan(ctx, skb)))
			return ipxl_resolve_failed_action(skb);
		if (unlikely(ipxl_skb_cb(skb)->frag_max_size))
			return IPXL_ACT_PRE_FRAG;

		if (unlikely(ipxl_46_translate(ctx, skb)))
			return ipxl_resolve_failed_action(skb);

		return IPXL_ACT_FWD;
	}

	netdev_dbg(ctx->dev, "Unsupported L3 proto: %u", proto);
	return IPXL_ACT_DROP;
}

void ipxl_mark_icmp_drop(struct sk_buff *skb, u8 type, u8 code, u32 info)
{
	struct ipxl_cb *cb = ipxl_skb_cb(skb);

	cb->emit_icmp_err = true;
	cb->icmp_err.type = type;
	cb->icmp_err.code = code;
	cb->icmp_err.info = info;
}

static void ipxl_46_emit_icmp_err(const struct ipxl_pkt_ctx *ctx,
				  struct sk_buff *inner)
{
	const struct iphdr *iph = ip_hdr(inner);
	struct ipxl_cb *cb = ipxl_skb_cb(inner);
	struct inet_skb_parm parm = { 0 };

	/* if inner has no dst metadata, build input route on the fly */
	if (unlikely(!skb_dst(inner))) {
		const int reason =
			ip_route_input_noref(inner, iph->daddr, iph->saddr,
					     ip4h_dscp(iph), inner->dev);

		if (unlikely(reason))
			return;
	}

	/* emit the ICMPv4 error */
	__icmp_send(inner, cb->icmp_err.type, cb->icmp_err.code,
		    htonl(cb->icmp_err.info), &parm);
}

static void ipxl_64_emit_icmp_err(const struct ipxl_pkt_ctx *ctx,
				  struct sk_buff *inner)
{
	struct ipxl_cb *cb = ipxl_skb_cb(inner);
	struct inet6_skb_parm parm = { 0 };
	struct in6_addr saddr;

	/* prefer configured pool6791v6 as ICMPv6 source but if unset (::),
	 * derive the source by translating pool6791v4 through pool6.
	 */
	if (!ipv6_addr_any(&ctx->cfg->pool6791v6))
		saddr = ctx->cfg->pool6791v6;
	else
		ipxl_addr_46(&ctx->cfg->pool6, ctx->cfg->pool6791v4.s_addr,
			     &saddr);

	/* emit the ICMPv6 error */
	icmp6_send(inner, cb->icmp_err.type, cb->icmp_err.code,
		   cb->icmp_err.info, &saddr, &parm);
}

int ipxl_emit_icmp_error(const struct ipxl_pkt_ctx *ctx, struct sk_buff *inner)
{
	switch (ntohs(inner->protocol)) {
	case ETH_P_IPV6:
		ipxl_64_emit_icmp_err(ctx, inner);
		return 0;
	case ETH_P_IP:
		ipxl_46_emit_icmp_err(ctx, inner);
		return 0;
	default:
		DEBUG_NET_WARN_ON_ONCE(1);
		return -EINVAL;
	}
}

static unsigned int ipxl_frag_dst_get_mtu(const struct dst_entry *dst)
{
	return dst->dev->mtu;
}

static struct dst_ops ipxl_frag_dst_ops = {
	.family = AF_UNSPEC,
	.mtu = ipxl_frag_dst_get_mtu,
};

static int ipxl_46_frag_output(struct net *net, struct sock *sk,
			       struct sk_buff *skb);

static int ipxl_46_do_fragment(struct ipxl_priv *ipxl, struct sk_buff *skb,
			       u16 frag_max_size)
{
	const unsigned long orig_dst = skb->_skb_refdst;
	struct rtable ipxl_rt = { 0 };
	int err;

	/* Initialize the dst entry so the stack can treat it as a valid
	 * route/dst object during fragmentation.
	 * Arguments are:
	 * - the dst entry to initialize,
	 * - the ops table for this dst type providing the translator's MTU,
	 * - device to netdev_hold if non-NULL,
	 * - DST_OBSOLETE_NONE: dst initial state is considered valid,
	 * - DST_NOCOUNT: don't account this dst in global dst stats as it's a
	 *   temporary synthetic dst.
	 */
	dst_init(&ipxl_rt.dst, &ipxl_frag_dst_ops, NULL, DST_OBSOLETE_NONE,
		 DST_NOCOUNT);

	/* set translator as the dst device (used for ipxl_fraf_dst_get_mtu) */
	ipxl_rt.dst.dev = ipxl->dev;

	/* setup the skb for fragmentation */
	skb_dst_set_noref(skb, &ipxl_rt.dst);
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	IPCB(skb)->frag_max_size = frag_max_size;

	/* fragment and reinject each frag in the translator */
	err = ip_do_fragment(dev_net(ipxl->dev), skb->sk, skb,
			     ipxl_46_frag_output);

	/* drop the original dst ref: we replaced skb->_skb_refdst with a
	 * temporary synthetic NOREF dst for fragmentation
	 */
	refdst_drop(orig_dst);

	return err;
}

static void ipxl_forward_pkt(struct ipxl_priv *ipxl, struct sk_buff *skb)
{
	const unsigned int len = skb->len;
	int err;

	/* prepare for reinjection */
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, false);

	err = gro_cells_receive(&ipxl->gro_cells, skb);
	if (likely(err == NET_RX_SUCCESS))
		dev_dstats_rx_add(ipxl->dev, len);
}

int ipxl_process_skb(struct ipxl_priv *ipxl, struct sk_buff *skb,
		     bool allow_pre_frag)
{
	const struct ipxl_cfg *cfg;
	struct ipxl_pkt_ctx ctx;
	enum ipxl_action action;
	int err = -EINVAL;

	/* TODO: consider switching to refcounted cfg get/put so we can
	 * shorten this RCU read-side critical section in the data path.
	 */
	rcu_read_lock();
	cfg = rcu_dereference(ipxl->cfg);
	if (unlikely(!cfg)) {
		rcu_read_unlock();
		dev_dstats_tx_dropped(ipxl->dev);
		kfree_skb(skb);
		return -ENODEV;
	}

	ctx.dev = ipxl->dev;
	ctx.cfg = cfg;

	action = ipxl_translate(&ctx, skb);
	switch (action) {
	case IPXL_ACT_FWD:
		dev_dstats_tx_add(ipxl->dev, skb->len);
		rcu_read_unlock();
		ipxl_forward_pkt(ipxl, skb);
		return 0;
	case IPXL_ACT_PRE_FRAG:
		rcu_read_unlock();
		/* prefrag is allowed only once to avoid unbounded loops */
		if (unlikely(!allow_pre_frag)) {
			err = -ELOOP;
			goto out_free;
		}

		err = ipxl_46_do_fragment(ipxl, skb,
					  ipxl_skb_cb(skb)->frag_max_size);
		/* fragment path already consumed/freed skb */
		skb = NULL;
		if (unlikely(err))
			goto out_free;
		return 0;
	case IPXL_ACT_ICMP_ERR:
		err = ipxl_emit_icmp_error(&ctx, skb);
		rcu_read_unlock();
		if (err)
			goto out_free;
		consume_skb(skb);
		return 0;
	case IPXL_ACT_DROP:
		rcu_read_unlock();
		goto out_free;
	default:
		rcu_read_unlock();
		DEBUG_NET_WARN_ON_ONCE(1);
		goto out_free;
	}

out_free:
	dev_dstats_tx_dropped(ipxl->dev);
	kfree_skb(skb);
	return err;
}

static int ipxl_46_frag_output(struct net *net, struct sock *sk,
			       struct sk_buff *skb)
{
	struct ipxl_priv *ipxl = netdev_priv(skb->dev);

	return ipxl_process_skb(ipxl, skb, false);
}

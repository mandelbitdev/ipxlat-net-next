// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h>

#include <net/ip.h>

#include "log.h"
#include "main.h"
#include "netlink.h"
#include "packet.h"
#include "rfc7915.h"
#include "translation_state.h"

MODULE_AUTHOR("Alberto Leiva Popper, Antonio Quartulli");
MODULE_DESCRIPTION("IPv6-IPv4 packet translation virtual device (RFC 7915)");
MODULE_LICENSE("GPL v2");

#define DRV_NAME "ipxlat"

static unsigned int ipxl_frag_dst_get_mtu(const struct dst_entry *dst)
{
	return dst->dev->mtu;
}

static struct dst_ops ipxl_frag_dst_ops = {
	.family = AF_UNSPEC,
	.mtu = ipxl_frag_dst_get_mtu,
};

static const struct ipxl_cfg ipxl_cfg_defaults = {
	/* 64:ff9b::/96 */
	.pool6.addr.s6_addr32[0] = htonl(0x0064ff9b),
	.pool6.len = 96,

	.pool6791v4.s_addr = htonl(INADDR_DUMMY),

	.lowest_ipv6_mtu = 1280,
	.plateaus.values = {
		65535, 32000, 17914, 8166, 4352, 2002, 1492,
	},
	.plateaus.count = 7,
	.compute_udp_csum_zero = false,
};

static int ipxl_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int ipxl_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static int ipxl_dev_init(struct net_device *dev)
{
	struct ipxl_priv *ipxl = netdev_priv(dev);
	struct ipxl_cfg *cfg;
	int err;

	cfg = kmemdup(&ipxl_cfg_defaults, sizeof(*cfg), GFP_KERNEL);
	if (unlikely(!cfg))
		return -ENOMEM;

	rcu_assign_pointer(ipxl->cfg, cfg);

	err = gro_cells_init(&ipxl->gro_cells, dev);
	if (unlikely(err)) {
		RCU_INIT_POINTER(ipxl->cfg, NULL);
		kfree(cfg);
		return err;
	}

	return 0;
}

static void ipxl_dev_uninit(struct net_device *dev)
{
	struct ipxl_priv *ipxl = netdev_priv(dev);
	struct ipxl_cfg *cfg;

	gro_cells_destroy(&ipxl->gro_cells);

	mutex_lock(&ipxl->cfg_lock);
	cfg = rcu_dereference_protected(ipxl->cfg,
					lockdep_is_held(&ipxl->cfg_lock));
	RCU_INIT_POINTER(ipxl->cfg, NULL);
	mutex_unlock(&ipxl->cfg_lock);

	synchronize_rcu();
	kfree(cfg);
}

static void ipxl_forward_pkt(struct ipxl_priv *ipxl, struct sk_buff *skb)
{
	struct sk_buff *next;

	for (; skb != NULL; skb = next) {
		next = skb->next;
		skb->next = NULL;
		skb_scrub_packet(skb, false);
		skb->dev = ipxl->dev;
		memset(skb->cb, 0, sizeof(skb->cb));
		gro_cells_receive(&ipxl->gro_cells, skb);
	}
}

static int ipxl_46_frag_output(struct net *net, struct sock *sk,
			       struct sk_buff *skb);

/* this pattern is used at least twice in the kernel:
 * - ovs_fragment()
 * - sch_fragment()
 */
static int ipxl_46_do_fragment(struct ipxl_priv *ipxl, struct sk_buff *skb,
			       __u16 frag_max_size)
{
	struct rtable ipxl_rt = { 0 };
	unsigned long orig_dst;
	int err;

	dst_init(&ipxl_rt.dst, &ipxl_frag_dst_ops, NULL,
		 DST_OBSOLETE_NONE, DST_NOCOUNT);
	ipxl_rt.dst.dev = ipxl->dev;

	orig_dst = skb->_skb_refdst;
	skb_dst_set_noref(skb, &ipxl_rt.dst);

	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	IPCB(skb)->frag_max_size = frag_max_size;

	err = ip_do_fragment(dev_net(ipxl->dev), skb->sk, skb,
			     ipxl_46_frag_output);
	refdst_drop(orig_dst);

	return err;
}

static int ipxl_process_skb(struct ipxl_priv *ipxl, struct sk_buff *skb,
			    bool allow_pre_frag)
{
	enum ipxl_xlat_action action;
	const struct ipxl_cfg *cfg;
	struct ipxl_pkt_ctx ctx;
	__u16 frag_max_size;
	int err;

	rcu_read_lock();
	cfg = rcu_dereference(ipxl->cfg);
	if (unlikely(!cfg)) {
		rcu_read_unlock();
		atomic64_inc(&ipxl->dropped);
		kfree_skb(skb);
		return -ENODEV;
	}

	ctx.dev = ipxl->dev;
	ctx.cfg = cfg;
	action = ipxl_xlat(&ctx, skb);
	switch (action) {
	case IPXL_XLAT_ACT_FWD:
		rcu_read_unlock();
		ipxl_forward_pkt(ipxl, skb);
		return 0;
	case IPXL_XLAT_ACT_PRE_FRAG:
		frag_max_size = ipxl_skb_cb(skb)->frag_max_size;
		rcu_read_unlock();
		/* if this is already a pre-fragmented packet, bail out */
		if (unlikely(!allow_pre_frag)) {
			atomic64_inc(&ipxl->dropped);
			kfree_skb(skb);
			return -ELOOP;
		}

		err = ipxl_46_do_fragment(ipxl, skb, frag_max_size);
		if (unlikely(err))
			atomic64_inc(&ipxl->dropped);
		return err;
	case IPXL_XLAT_ACT_ICMP_ERR:
		err = ipxl_emit_icmp_error(&ctx, skb);
		rcu_read_unlock();
		if (unlikely(err))
			atomic64_inc(&ipxl->dropped);
		kfree_skb(skb);
		return err;
	case IPXL_XLAT_ACT_DROP:
		rcu_read_unlock();
		atomic64_inc(&ipxl->dropped);
		kfree_skb(skb);
		return -EINVAL;
	}

	rcu_read_unlock();
	atomic64_inc(&ipxl->dropped);
	kfree_skb(skb);
	return -EINVAL;
}

static int ipxl_46_frag_output(struct net *net, struct sock *sk,
			       struct sk_buff *skb)
{
	struct ipxl_priv *ipxl = netdev_priv(skb->dev);

	log_debug("Processing a prefragmented packet.");
	return ipxl_process_skb(ipxl, skb, false);
}

static int ipxl_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipxl_priv *ipxl = netdev_priv(dev);

	log_debug("Received a packet.");
	ipxl_process_skb(ipxl, skb, true);
	return NETDEV_TX_OK;
}

static __u32 addr6_get_bit(const struct in6_addr *addr, unsigned int pos)
{
	__u32 quadrant; /* As in, @addr has 4 "quadrants" of 32 bits each. */
	__u32 mask;

	/* "pos >> 5" is a more efficient version of "pos / 32". */
	quadrant = be32_to_cpu(addr->s6_addr32[pos >> 5]);
	/* "pos & 0x1FU" is a more efficient version of "pos % 32". */
	mask = 1U << (31 - (pos & 0x1FU));

	return quadrant & mask;
}

int ipxl_prefix6_validate(const struct ipv6_prefix *prefix)
{
	unsigned int i;

	if (prefix->len != 32 && prefix->len != 40 && prefix->len != 48 &&
	    prefix->len != 56 && prefix->len != 64 && prefix->len != 96) {
		pr_err("Unsupported RFC6052 prefix length: %u.\n", prefix->len);
		return -EINVAL;
	}

	if (prefix->len > 128) {
		pr_err("Prefix length %u is too high.\n", prefix->len);
		return -EINVAL;
	}

	for (i = prefix->len; i < 128; i++) {
		if (addr6_get_bit(&prefix->addr, i)) {
			pr_err("'%pI6c/%u' seems to have a suffix; please fix.\n",
			       &prefix->addr, prefix->len);
			return -EINVAL;
		}
	}

	return 0;
}

static const struct net_device_ops ipxl_netdev_ops = {
	.ndo_init = ipxl_dev_init,
	.ndo_uninit = ipxl_dev_uninit,
	.ndo_open = ipxl_open,
	.ndo_stop = ipxl_stop,
	.ndo_start_xmit = ipxl_start_xmit,
};

static const struct device_type ipxl_type = {
	.name = DRV_NAME,
};

static void ipxl_setup(struct net_device *dev)
{
	struct ipxl_priv *ipxl = netdev_priv(dev);
	netdev_features_t feat = NETIF_F_SG | NETIF_F_FRAGLIST |
				 NETIF_F_HW_CSUM | NETIF_F_RXCSUM |
				 NETIF_F_HIGHDMA | NETIF_F_GSO_SOFTWARE;

	dev->type = ARPHRD_NONE;
	dev->flags |= IFF_NOARP;
	dev->priv_flags |= IFF_NO_QUEUE;

	dev->lltx = true;
	dev->features |= feat;
	dev->hw_features |= feat;
	dev->hw_enc_features |= feat;

	dev->netdev_ops = &ipxl_netdev_ops;
	dev->needs_free_netdev = true;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
	dev->max_mtu =
		IP_MAX_MTU - sizeof(struct ipv6hdr) - sizeof(struct iphdr);
	dev->min_mtu = IPV6_MIN_MTU;
	dev->mtu = ETH_DATA_LEN;

	SET_NETDEV_DEVTYPE(dev, &ipxl_type);

	ipxl->dev = dev;
	RCU_INIT_POINTER(ipxl->cfg, NULL);
	mutex_init(&ipxl->cfg_lock);
	atomic64_set(&ipxl->dropped, 0);
}

/*
 * Inherited from veth.c. I have no idea why it exists.
 *
 * 	ip link add type siit numtxqueues 5 numrxqueues 6
 *
 * results in
 *
 *	dev->num_tx_queues: 5
 *	dev->num_rx_queues: 6
 *	dev->real_num_tx_queues: 5
 *	dev->real_num_rx_queues: 6
 *
 * If numtxqueues/numrxqueues default, rtnl_create_link() uses
 * ipxl_get_num_queues() to set num_tx_queues/num_rx_queues. In my quad core,
 * this results in
 *
 *	dev->num_tx_queues: 4
 *	dev->num_rx_queues: 4
 *	dev->real_num_tx_queues: 4
 *	dev->real_num_rx_queues: 4
 *
 * Then this function downgrades the last two to 1.
 *
 * This looks like nonsense.
 */
static int ipxl_init_queues(struct net_device *dev, struct nlattr *tb[])
{
	int err;

	if (!tb[IFLA_NUM_TX_QUEUES] && dev->num_tx_queues > 1) {
		err = netif_set_real_num_tx_queues(dev, 1);
		if (err)
			return err;
	}
	if (!tb[IFLA_NUM_RX_QUEUES] && dev->num_rx_queues > 1) {
		err = netif_set_real_num_rx_queues(dev, 1);
		if (err)
			return err;
	}

	return 0;
}

/* https://github.com/torvalds/linux/commit/872f690341948b502c93318f806d821c5 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define NLA_STRCPY nla_strscpy
#else
#define NLA_STRCPY nla_strlcpy
#endif

/*
 * Simplified version of veth's newlink.
 */
static int ipxl_newlink(struct net_device *dev,
			struct rtnl_newlink_params *params,
			struct netlink_ext_ack *extack)
{
	struct nlattr **tb = params->tb;
	int err;

	if (tb[IFLA_IFNAME])
		NLA_STRCPY(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	err = register_netdevice(dev);
	if (err < 0)
		return err;

	pr_info("Added device '%s'.\n", dev->name);

	err = ipxl_init_queues(dev, tb);
	if (err) {
		unregister_netdevice(dev);
		return err;
	}

	return 0;
}

/*
 * Inherited from veth. Not actually needed; if dellink is NULL,
 * __rtnl_link_register() automatically sets it as unregister_netdevice_queue().
 *
 * TODO If you don't add anything, probably delete this function on pr_info()
 * purge day.
 */
static void ipxl_dellink(struct net_device *dev, struct list_head *head)
{
	pr_info("Removing device '%s'.\n", dev->name);
	unregister_netdevice_queue(dev, head);
}

/*
 * Inherited from veth. Seems like a reasonable implementation.
 */
static unsigned int ipxl_get_num_queues(void)
{
	int queues = num_possible_cpus();
	return (queues > 4096) ? 4096 : queues;
}

static struct rtnl_link_ops ipxl_link_ops = {
	.kind = DRV_NAME,
	.priv_size = sizeof(struct ipxl_priv),
	.setup = ipxl_setup,
	.newlink = ipxl_newlink,
	.dellink = ipxl_dellink,

	/* nlargs not needed for now, so .policy and .maxtype excluded */

	/*
	 * It seems veth uses .get_link_net to return the peer dev's namespace.
	 * The kernel seems to only use this incidentally (as an ugly hack),
	 * and has no meaning in SIIT anyway.
	 */

	.get_num_tx_queues = ipxl_get_num_queues,
	.get_num_rx_queues = ipxl_get_num_queues,
};

bool ipxl_dev_is_valid(const struct net_device *dev)
{
	return dev->rtnl_link_ops == &ipxl_link_ops;
}

static int __init ipxl_init(void)
{
	int err;

	err = rtnl_link_register(&ipxl_link_ops);
	if (err)
		return err;

	err = ipxl_nl_register();
	if (err) {
		rtnl_link_unregister(&ipxl_link_ops);
		return err;
	}

	return 0;
}

static void __exit ipxl_exit(void)
{
	ipxl_nl_unregister();
	rtnl_link_unregister(&ipxl_link_ops);
}

module_init(ipxl_init);
module_exit(ipxl_exit);

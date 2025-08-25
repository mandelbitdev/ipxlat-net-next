// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/version.h>

#include "log.h"
#include "rfc7915.h"
#include "translation_state.h"

MODULE_AUTHOR("Alberto Leiva Popper, Antonio Quartulli");
MODULE_DESCRIPTION("IPv6-IPv4 packet translation virtual device (RFC 7915)");
MODULE_LICENSE("GPL v2");

#define DRV_NAME "ipxlat"

/* Inherited from veth, unused placeholder for now. */
struct ipxlat_priv {
	atomic64_t		dropped;
};

#define JCMD_POOL6		(SIOCDEVPRIVATE + 1)
#define JCMD_POOL6791V4		(SIOCDEVPRIVATE + 2)
#define JCMD_POOL6791V6		(SIOCDEVPRIVATE + 3)
#define JCMD_LI6M		(SIOCDEVPRIVATE + 4)
#define JCMD_AUCZ		(SIOCDEVPRIVATE + 5)

static struct jool_globals cfg = {
	/* 64:ff9b::/96 */
	.pool6.addr.s6_addr32[0] = htonl(0x0064ff9b),
	.pool6.len = 96,

	.pool6791v4.s_addr = htonl(INADDR_DUMMY),

	.lowest_ipv6_mtu = 1280,
	.plateaus.values = {
		65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68
	},
	.plateaus.count = 11,
	.compute_udp_csum_zero = false,
};

static int ipxlat_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int ipxlat_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static void send_packet(struct sk_buff *skb, struct net_device *dev)
{
	struct sk_buff *next;

	for (; skb != NULL; skb = next) {
		next = skb->next;
		skb->next = NULL;
		skb->dev = dev;
		memset(skb->cb, 0, sizeof(skb->cb));
		netif_rx(skb);
	}
}

static int ipxlat_start_xmit(struct sk_buff *in, struct net_device *dev)
{
	struct xlation state;

	log_debug("Received a packet.");

	memset(&state, 0, sizeof(state));
	state.ns = dev_net(dev);
	state.dev = dev;
	state.cfg = &cfg;

	jool_xlat(&state, in);
	dev_kfree_skb(in);

	if (state.out)
		send_packet(state.out, dev);

	return 0;
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

static int prefix6_validate(const struct ipv6_prefix *prefix)
{
	unsigned int i;

	if (prefix->len > 128) {
		pr_err("Prefix length %u is too high.\n", prefix->len);
		return EINVAL;
	}

	for (i = prefix->len; i < 128; i++) {
		if (addr6_get_bit(&prefix->addr, i)) {
			pr_err("'%pI6c/%u' seems to have a suffix; please fix.\n",
					&prefix->addr, prefix->len);
			return EINVAL;
		}
	}

	return 0;
}

static int ipxlat_siocdevprivate(struct net_device *dev, struct ifreq *ifr,
				 void __user *data, int cmd)
{
	union {
		struct ipv6_prefix p6;
		struct in6_addr a6;
		struct in_addr a4;
		uint32_t u32;
		uint8_t u8;
	} buf;
	int error;

	switch (cmd) {
	case JCMD_POOL6:
		error = copy_from_user(&buf.p6, data, sizeof(buf.p6));
		if (error)
			goto efault;
		error = prefix6_validate(&buf.p6);
		if (error)
			return error;
		cfg.pool6 = buf.p6;
		log_debug("new pool6: %pI6c/%u", &cfg.pool6.addr, cfg.pool6.len);
		return 0;

	case JCMD_POOL6791V6:
		error = copy_from_user(&buf.a6, data, sizeof(buf.a6));
		if (error)
			goto efault;
		cfg.pool6791v6 = buf.a6;
		log_debug("new pool6791v6: %pI6c", &cfg.pool6791v6);
		return 0;

	case JCMD_POOL6791V4:
		error = copy_from_user(&buf.a4, data, sizeof(buf.a4));
		if (error)
			goto efault;
		cfg.pool6791v4 = buf.a4;
		log_debug("new pool6791v4: %pI4", &cfg.pool6791v4);
		return 0;

	case JCMD_LI6M:
		error = copy_from_user(&buf.u32, data, sizeof(buf.u32));
		if (error)
			goto efault;
		if (buf.u32 < 1280) {
			pr_err("lowest-ipv6-mtu out of range: %u < 1280\n",
			       buf.u32);
			return -ERANGE;
		}
		cfg.lowest_ipv6_mtu = buf.u32;
		log_debug("new lowest-ipv6-mtu: %u", cfg.lowest_ipv6_mtu);
		return 0;

	case JCMD_AUCZ:
		error = copy_from_user(&buf.u8, data, sizeof(buf.u8));
		if (error)
			goto efault;
		cfg.compute_udp_csum_zero = buf.u8;
		log_debug("new amend-udp-checksum-zero: %u",
			  cfg.compute_udp_csum_zero);
		return 0;
	}

	log_debug("Unrecognized ioctl.");
	return 0;

efault:
	pr_err("copy_from_user() errored: %d\n", error);
	return -EFAULT;
}

static const struct net_device_ops ipxlat_netdev_ops = {
	.ndo_open		= ipxlat_open,
	.ndo_stop		= ipxlat_stop,
	.ndo_start_xmit		= ipxlat_start_xmit,
	.ndo_siocdevprivate	= ipxlat_siocdevprivate,
};

static const struct device_type ipxlat_type = {
	.name = DRV_NAME,
};

static void ipxlat_setup(struct net_device *dev)
{
	netdev_features_t feat = NETIF_F_SG | NETIF_F_FRAGLIST | \
				 NETIF_F_HW_CSUM | NETIF_F_RXCSUM | \
				 NETIF_F_HIGHDMA | NETIF_F_GSO_SOFTWARE;

	dev->type = ARPHRD_NONE;
	dev->flags |= IFF_NOARP;
	dev->priv_flags |= IFF_NO_QUEUE;

	dev->lltx = true;
	dev->features |= feat;
	dev->hw_features |= feat;
	dev->hw_enc_features |= feat;

	dev->netdev_ops = &ipxlat_netdev_ops;
	dev->needs_free_netdev = true;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
	dev->max_mtu = IP_MAX_MTU -
		sizeof(struct ipv6hdr) - sizeof(struct iphdr);
	dev->min_mtu = IPV6_MIN_MTU;
	dev->mtu = ETH_DATA_LEN;

	SET_NETDEV_DEVTYPE(dev, &ipxlat_type);
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
 * ipxlat_get_num_queues() to set num_tx_queues/num_rx_queues. In my quad core,
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
static int ipxlat_init_queues(struct net_device *dev, struct nlattr *tb[])
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
static int ipxlat_newlink(struct net_device *dev,
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

	err = ipxlat_init_queues(dev, tb);
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
static void ipxlat_dellink(struct net_device *dev, struct list_head *head)
{
	pr_info("Removing device '%s'.\n", dev->name);
	unregister_netdevice_queue(dev, head);
}

/*
 * Inherited from veth. Seems like a reasonable implementation.
 */
static unsigned int ipxlat_get_num_queues(void)
{
	int queues = num_possible_cpus();
	return (queues > 4096) ? 4096 : queues;
}

static struct rtnl_link_ops ipxlat_link_ops = {
	.kind			= DRV_NAME,
	.priv_size		= sizeof(struct ipxlat_priv),
	.setup			= ipxlat_setup,
	.newlink		= ipxlat_newlink,
	.dellink		= ipxlat_dellink,

	/* nlargs not needed for now, so .policy and .maxtype excluded */

	/*
	 * It seems veth uses .get_link_net to return the peer dev's namespace.
	 * The kernel seems to only use this incidentally (as an ugly hack),
	 * and has no meaning in SIIT anyway.
	 */

	.get_num_tx_queues	= ipxlat_get_num_queues,
	.get_num_rx_queues	= ipxlat_get_num_queues,
};

static int ipxlat_init(void)
{
	return rtnl_link_register(&ipxlat_link_ops);
}

static void ipxlat_exit(void)
{
	rtnl_link_unregister(&ipxlat_link_ops);
}

module_init(ipxlat_init);
module_exit(ipxlat_exit);

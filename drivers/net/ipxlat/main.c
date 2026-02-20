// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include <linux/module.h>
#include <linux/slab.h>

#include <net/ip.h>

#include "main.h"
#include "ipxlpriv.h"
#include "netlink.h"
#include "dispatch.h"

MODULE_AUTHOR("Alberto Leiva Popper, Antonio Quartulli");
MODULE_DESCRIPTION("IPv6-IPv4 packet translation virtual device (RFC 7915)");
MODULE_LICENSE("GPL v2");

#define DRV_NAME "ipxlat"

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

static int ipxl_dev_init(struct net_device *dev)
{
	struct ipxl_priv *ipxl = netdev_priv(dev);
	struct ipxl_cfg *cfg;
	int err;

	ipxl->dev = dev;
	mutex_init(&ipxl->cfg_lock);

	cfg = kmemdup(&ipxl_cfg_defaults, sizeof(*cfg), GFP_KERNEL);
	if (unlikely(!cfg))
		return -ENOMEM;

	err = gro_cells_init(&ipxl->gro_cells, dev);
	if (unlikely(err)) {
		kfree(cfg);
		return err;
	}

	rcu_assign_pointer(ipxl->cfg, cfg);
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

	/* wait until all readers are done before freeing the object */
	synchronize_rcu();
	kfree(cfg);
}

static int ipxl_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipxl_priv *ipxl = netdev_priv(dev);

	ipxl_process_skb(ipxl, skb, true);
	return NETDEV_TX_OK;
}

static const struct net_device_ops ipxl_netdev_ops = {
	.ndo_init = ipxl_dev_init,
	.ndo_uninit = ipxl_dev_uninit,
	.ndo_start_xmit = ipxl_start_xmit,
};

static const struct device_type ipxl_type = {
	.name = DRV_NAME,
};

static void ipxl_setup(struct net_device *dev)
{
	const netdev_features_t feat = NETIF_F_SG | NETIF_F_FRAGLIST |
				       NETIF_F_HW_CSUM | NETIF_F_HIGHDMA |
				       NETIF_F_GSO_SOFTWARE;

	dev->type = ARPHRD_NONE;
	dev->flags = IFF_NOARP;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->hard_header_len = 0;
	dev->addr_len = 0;

	dev->lltx = true;
	dev->features |= feat;
	dev->hw_features |= feat;
	dev->hw_enc_features |= feat;

	dev->netdev_ops = &ipxl_netdev_ops;
	dev->needs_free_netdev = true;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_DSTATS;
	dev->max_mtu =
		IP_MAX_MTU - sizeof(struct ipv6hdr) - sizeof(struct iphdr);
	dev->min_mtu = IPV6_MIN_MTU;
	dev->mtu = ETH_DATA_LEN;

	/* keep skb->dst up to ndo_start_xmit as we may need routing context
	 * later when generating ICMP errors on translated packets
	 */
	netif_keep_dst(dev);

	SET_NETDEV_DEVTYPE(dev, &ipxl_type);
}

static struct rtnl_link_ops ipxl_link_ops = {
	.kind = DRV_NAME,
	.priv_size = sizeof(struct ipxl_priv),
	.setup = ipxl_setup,
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

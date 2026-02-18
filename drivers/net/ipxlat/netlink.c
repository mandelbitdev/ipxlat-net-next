// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include <net/genetlink.h>
#include <linux/inetdevice.h>
#include <linux/slab.h>
#include <net/ipv6.h>

#include <uapi/linux/ipxlat.h>

#include "main.h"
#include "netlink.h"
#include "netlink-gen.h"
#include "translation_state.h"

/* TODO: look at net/shaper/shaper.c */

MODULE_ALIAS_GENL_FAMILY(IPXLAT_FAMILY_NAME);

struct ipxl_nl_info_ctx {
	struct ipxl_priv *ipxl;
	netdevice_tracker tracker;
};

struct ipxl_nl_dump_ctx {
	unsigned long last_ifindex;
};

/**
 * ipxl_get_dev_from_attrs - retrieve the ipxlat private data from the
 *			     netdevice a netlink message is targeting
 * @net: network namespace where to look for the interface
 * @info: generic netlink info from the user request
 * @tracker: tracker object to be used for the netdev reference acquisition
 *
 * Return: the ipxlat private data, if found, or an error otherwise
 */
static struct ipxl_priv *ipxl_get_from_attrs(struct net *net,
					     struct genl_info *info,
					     netdevice_tracker *tracker)
{
	struct ipxl_priv *ipxl;
	struct net_device *dev;
	int ifindex;

	if (GENL_REQ_ATTR_CHECK(info, IPXLAT_A_DEV_IFINDEX))
		return ERR_PTR(-EINVAL);

	ifindex = nla_get_u32(info->attrs[IPXLAT_A_DEV_IFINDEX]);

	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, ifindex);
	if (!dev) {
		rcu_read_unlock();
		NL_SET_ERR_MSG_MOD(info->extack,
				   "ifindex does not match any interface");
		return ERR_PTR(-ENODEV);
	}

	if (!ipxl_dev_is_valid(dev)) {
		rcu_read_unlock();
		NL_SET_ERR_MSG_MOD(info->extack,
				   "specified interface is not ipxlat");
		NL_SET_BAD_ATTR(info->extack,
				info->attrs[IPXLAT_A_DEV_IFINDEX]);
		return ERR_PTR(-EINVAL);
	}

	ipxl = netdev_priv(dev);
	netdev_hold(dev, tracker, GFP_ATOMIC);
	rcu_read_unlock();

	return ipxl;
}

int ipxlat_nl_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		       struct genl_info *info)
{
	struct ipxl_nl_info_ctx *ctx = (struct ipxl_nl_info_ctx *)info->ctx;
	struct ipxl_priv *ipxl;

	BUILD_BUG_ON(sizeof(*ctx) > sizeof(info->ctx));

	ipxl = ipxl_get_from_attrs(genl_info_net(info), info, &ctx->tracker);
	if (IS_ERR(ipxl))
		return PTR_ERR(ipxl);

	ctx->ipxl = ipxl;
	return 0;
}

void ipxlat_nl_post_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
			 struct genl_info *info)
{
	struct ipxl_nl_info_ctx *ctx = (struct ipxl_nl_info_ctx *)info->ctx;

	if (ctx->ipxl)
		netdev_put(ctx->ipxl->dev, &ctx->tracker);
}

static int ipxl_nl_send_dev(struct sk_buff *skb, const struct ipxl_priv *ipxl,
			    struct net *src_net, const u32 portid,
			    const u32 seq, int flags)
{
	struct nlattr *attr_cfg, *attr_pool;
	struct ipxl_cfg cfg_snapshot;
	const struct ipxl_cfg *cfg;
	int id, ret = -EMSGSIZE;
	void *hdr;

	rcu_read_lock();
	cfg = rcu_dereference(ipxl->cfg);
	if (unlikely(!cfg)) {
		rcu_read_unlock();
		return -ENODEV;
	}
	cfg_snapshot = *cfg;
	rcu_read_unlock();
	cfg = &cfg_snapshot;

	hdr = genlmsg_put(skb, portid, seq, &ipxlat_nl_family, flags,
			  IPXLAT_CMD_DEV_GET);
	if (!hdr)
		return -ENOBUFS;

	if (nla_put_u32(skb, IPXLAT_A_DEV_IFINDEX, ipxl->dev->ifindex))
		goto err;

	if (!net_eq(src_net, dev_net(ipxl->dev))) {
		id = peernet2id_alloc(src_net, dev_net(ipxl->dev),
				      GFP_ATOMIC);
		if (id < 0) {
			ret = id;
			goto err;
		}
		if (nla_put_s32(skb, IPXLAT_A_DEV_NETNSID, id))
			goto err;
	}

	attr_cfg = nla_nest_start(skb, IPXLAT_A_DEV_CONFIG);
	if (!attr_cfg)
		goto err;

	attr_pool = nla_nest_start(skb, IPXLAT_A_CFG_POOL6);
	if (!attr_pool)
		goto err;

	if (nla_put_in6_addr(skb, IPXLAT_A_POOL_PREFIX, &cfg->pool6.addr) ||
	    nla_put_u8(skb, IPXLAT_A_POOL_PREFIX_LEN, cfg->pool6.len))
		goto err;

	nla_nest_end(skb, attr_pool);

	if (nla_put_in6_addr(skb, IPXLAT_A_CFG_POOL6791V6, &cfg->pool6791v6) ||
	    nla_put_in_addr(skb, IPXLAT_A_CFG_POOL6791V4,
			    cfg->pool6791v4.s_addr) ||
	    nla_put_u32(skb, IPXLAT_A_CFG_LOWEST_IPV6_MTU,
			cfg->lowest_ipv6_mtu) ||
	    nla_put_u8(skb, IPXLAT_A_CFG_COMPUTE_UDP_CSUM_ZERO,
		       cfg->compute_udp_csum_zero))
		goto err;

	nla_nest_end(skb, attr_cfg);
	genlmsg_end(skb, hdr);

	return 0;
err:
	genlmsg_cancel(skb, hdr);
	return ret;
}

int ipxlat_nl_dev_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct ipxl_nl_info_ctx *ctx = (struct ipxl_nl_info_ctx *)info->ctx;
	struct sk_buff *reply;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, IPXLAT_A_DEV_IFINDEX))
		return -EINVAL;

	reply = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	ret = ipxl_nl_send_dev(reply, ctx->ipxl, genl_info_net(info),
			       info->snd_portid, info->snd_seq, 0);
	if (ret < 0) {
		nlmsg_free(reply);
		return ret;
	}

	return genlmsg_reply(reply, info);
}

int ipxlat_nl_dev_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ipxl_nl_dump_ctx *state = (struct ipxl_nl_dump_ctx *)cb->ctx;
	struct net *net = sock_net(cb->skb->sk);
	netdevice_tracker tracker;
	struct net_device *dev;
	int ret;

	rcu_read_lock();
	for_each_netdev_dump(net, dev, state->last_ifindex) {
		if (!ipxl_dev_is_valid(dev))
			continue;

		netdev_hold(dev, &tracker, GFP_ATOMIC);
		rcu_read_unlock();

		ret = ipxl_nl_send_dev(skb, netdev_priv(dev), net,
				       NETLINK_CB(cb->skb).portid,
				       cb->nlh->nlmsg_seq, NLM_F_MULTI);

		rcu_read_lock();
		netdev_put(dev, &tracker);

		if (ret < 0) {
			if (ret == -EMSGSIZE && skb->len > 0)
				break;

			rcu_read_unlock();
			return ret;
		}
	}
	rcu_read_unlock();

	return skb->len;
}

static int ipxl_nl_parse_pool6(struct nlattr *attr, struct ipv6_prefix *pool6,
			       struct netlink_ext_ack *extack)
{
	struct nlattr *attrs_pool[IPXLAT_A_POOL_MAX + 1];
	struct ipv6_prefix new_pool6;
	struct in6_addr masked;
	int ret;

	new_pool6 = *pool6;

	ret = nla_parse_nested(attrs_pool, IPXLAT_A_POOL_MAX, attr,
			       ipxlat_pool_nl_policy, extack);
	if (ret)
		return ret;

	if (!attrs_pool[IPXLAT_A_POOL_PREFIX] &&
	    !attrs_pool[IPXLAT_A_POOL_PREFIX_LEN]) {
		NL_SET_ERR_MSG_MOD(extack, "pool6 update is empty");
		return -EINVAL;
	}

	if (attrs_pool[IPXLAT_A_POOL_PREFIX])
		new_pool6.addr =
			nla_get_in6_addr(attrs_pool[IPXLAT_A_POOL_PREFIX]);
	if (attrs_pool[IPXLAT_A_POOL_PREFIX_LEN])
		new_pool6.len =
			nla_get_u8(attrs_pool[IPXLAT_A_POOL_PREFIX_LEN]);

	/* masked = pfx->addr with host bits cleared */
	ipv6_addr_prefix(&masked, &new_pool6.addr, new_pool6.len);

	/* if they differ, there were host bits set */
	if (!ipv6_addr_equal(&new_pool6.addr, &masked)) {
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "'%pI6c/%u' has non-zero host bits",
				       &new_pool6.addr, new_pool6.len);
		return -EINVAL;
	}

	ret = ipxl_prefix6_validate(&new_pool6);
	if (ret) {
		if (attrs_pool[IPXLAT_A_POOL_PREFIX_LEN])
			NL_SET_BAD_ATTR(extack,
					attrs_pool[IPXLAT_A_POOL_PREFIX_LEN]);
		else
			NL_SET_BAD_ATTR(extack,
					attrs_pool[IPXLAT_A_POOL_PREFIX]);
		return ret;
	}

	*pool6 = new_pool6;
	return 0;
}

static int ipxl_nl_validate_pool6791v4(__be32 addr,
				       struct netlink_ext_ack *extack)
{
	if (unlikely(ipv4_is_zeronet(addr) || ipv4_is_loopback(addr) ||
		     ipv4_is_multicast(addr) || ipv4_is_lbcast(addr) ||
		     ipv4_is_linklocal_169(addr))) {
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "invalid pool6791v4 address: %pI4",
				       &addr);
		return -EINVAL;
	}

	return 0;
}

static int ipxl_nl_validate_pool6791v6(const struct in6_addr *addr,
				       struct netlink_ext_ack *extack)
{
	int type;

	if (likely(ipv6_addr_any(addr)))
		return 0;

	type = ipv6_addr_type(addr);
	if (unlikely(!(type & IPV6_ADDR_UNICAST) ||
		     (type & IPV6_ADDR_MULTICAST) ||
		     (type & IPV6_ADDR_LOOPBACK) ||
		     (type & IPV6_ADDR_LINKLOCAL) ||
		     (type & IPV6_ADDR_MAPPED))) {
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "invalid pool6791v6 address: %pI6c",
				       addr);
		return -EINVAL;
	}

	return 0;
}

int ipxlat_nl_dev_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct ipxl_nl_info_ctx *ctx = (struct ipxl_nl_info_ctx *)info->ctx;
	struct nlattr *attrs[IPXLAT_A_CFG_MAX + 1];
	struct ipxl_cfg *cfg_old, *cfg_new;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, IPXLAT_A_DEV_CONFIG))
		return -EINVAL;

	ret = nla_parse_nested(attrs, IPXLAT_A_CFG_MAX,
			       info->attrs[IPXLAT_A_DEV_CONFIG],
			       ipxlat_cfg_nl_policy, info->extack);
	if (ret)
		return ret;
	/* TODO: Refactor config parsing into a dedicated typed helper and
	 * unify decode/validation flow for all cfg attributes.
	 */

	if (!attrs[IPXLAT_A_CFG_POOL6] && !attrs[IPXLAT_A_CFG_POOL6791V6] &&
	    !attrs[IPXLAT_A_CFG_POOL6791V4] &&
	    !attrs[IPXLAT_A_CFG_LOWEST_IPV6_MTU] &&
	    !attrs[IPXLAT_A_CFG_COMPUTE_UDP_CSUM_ZERO]) {
		NL_SET_ERR_MSG_MOD(info->extack, "config update is empty");
		return -EINVAL;
	}

	cfg_new = kmalloc(sizeof(*cfg_new), GFP_KERNEL);
	if (unlikely(!cfg_new))
		return -ENOMEM;

	mutex_lock(&ctx->ipxl->cfg_lock);
	cfg_old =
		rcu_dereference_protected(ctx->ipxl->cfg,
					  lockdep_is_held(&ctx->ipxl->cfg_lock));
	if (unlikely(!cfg_old)) {
		ret = -ENODEV;
		goto out_unlock_free_new;
	}
	*cfg_new = *cfg_old;

	if (attrs[IPXLAT_A_CFG_POOL6]) {
		ret = ipxl_nl_parse_pool6(attrs[IPXLAT_A_CFG_POOL6],
					  &cfg_new->pool6, info->extack);
		if (ret)
			goto out_unlock_free_new;
	}
	if (attrs[IPXLAT_A_CFG_POOL6791V6])
		cfg_new->pool6791v6 =
			nla_get_in6_addr(attrs[IPXLAT_A_CFG_POOL6791V6]);
	if (attrs[IPXLAT_A_CFG_POOL6791V4])
		cfg_new->pool6791v4.s_addr =
			nla_get_in_addr(attrs[IPXLAT_A_CFG_POOL6791V4]);
	if (attrs[IPXLAT_A_CFG_LOWEST_IPV6_MTU])
		cfg_new->lowest_ipv6_mtu =
			nla_get_u32(attrs[IPXLAT_A_CFG_LOWEST_IPV6_MTU]);
	if (attrs[IPXLAT_A_CFG_COMPUTE_UDP_CSUM_ZERO])
		cfg_new->compute_udp_csum_zero =
			!!nla_get_u8(attrs[IPXLAT_A_CFG_COMPUTE_UDP_CSUM_ZERO]);

	if (attrs[IPXLAT_A_CFG_POOL6791V6]) {
		ret = ipxl_nl_validate_pool6791v6(&cfg_new->pool6791v6,
						  info->extack);
		if (ret) {
			NL_SET_BAD_ATTR(info->extack,
					attrs[IPXLAT_A_CFG_POOL6791V6]);
			goto out_unlock_free_new;
		}
	}

	if (attrs[IPXLAT_A_CFG_POOL6791V4]) {
		ret = ipxl_nl_validate_pool6791v4(cfg_new->pool6791v4.s_addr,
						  info->extack);
		if (ret) {
			NL_SET_BAD_ATTR(info->extack,
					attrs[IPXLAT_A_CFG_POOL6791V4]);
			goto out_unlock_free_new;
		}
	}

	rcu_assign_pointer(ctx->ipxl->cfg, cfg_new);
	mutex_unlock(&ctx->ipxl->cfg_lock);

	synchronize_rcu();
	kfree(cfg_old);

	return 0;

out_unlock_free_new:
	mutex_unlock(&ctx->ipxl->cfg_lock);
	kfree(cfg_new);
	return ret;
}

/**
 * ipxl_nl_register - perform any needed registration in the NL subsystem
 *
 * Return: 0 on success, a negative error code otherwise
 */
int __init ipxl_nl_register(void)
{
	int ret = genl_register_family(&ipxlat_nl_family);

	if (ret)
		pr_err("ipxlat: genl_register_family failed: %d\n", ret);

	return ret;
}

/**
 * ipxl_nl_unregister - undo any module wide netlink registration
 */
void ipxl_nl_unregister(void)
{
	genl_unregister_family(&ipxlat_nl_family);
}

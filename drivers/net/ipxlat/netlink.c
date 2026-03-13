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

#include <net/genetlink.h>
#include <net/ipv6.h>

#include <uapi/linux/ipxl.h>

#include "netlink.h"
#include "main.h"
#include "netlink-gen.h"
#include "ipxlpriv.h"

MODULE_ALIAS_GENL_FAMILY(IPXL_FAMILY_NAME);

struct ipxl_nl_info_ctx {
	struct ipxl_priv *ipxl;
	netdevice_tracker tracker;
};

struct ipxl_nl_dump_ctx {
	unsigned long last_ifindex;
};

/**
 * ipxl_get_from_attrs - retrieve ipxlat private data for target netdev
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

	if (GENL_REQ_ATTR_CHECK(info, IPXL_A_DEV_IFINDEX))
		return ERR_PTR(-EINVAL);
	ifindex = nla_get_u32(info->attrs[IPXL_A_DEV_IFINDEX]);

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
		NL_SET_BAD_ATTR(info->extack, info->attrs[IPXL_A_DEV_IFINDEX]);
		return ERR_PTR(-EINVAL);
	}

	ipxl = netdev_priv(dev);
	netdev_hold(dev, tracker, GFP_ATOMIC);
	rcu_read_unlock();

	return ipxl;
}

int ipxl_nl_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
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

void ipxl_nl_post_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		       struct genl_info *info)
{
	struct ipxl_nl_info_ctx *ctx = (struct ipxl_nl_info_ctx *)info->ctx;

	if (ctx->ipxl)
		netdev_put(ctx->ipxl->dev, &ctx->tracker);
}

static int ipxl_nl_send_dev(struct sk_buff *skb, struct ipxl_priv *ipxl,
			    struct net *src_net, const u32 portid,
			    const u32 seq, int flags)
{
	struct nlattr *attr_cfg, *attr_pool;
	struct ipv6_prefix xlat_prefix6;
	int id, ret = -EMSGSIZE;
	u32 lowest_ipv6_mtu;
	void *hdr;

	/* snapshot cfg under lock so userspace sees a coherent device config */
	mutex_lock(&ipxl->cfg_lock);
	xlat_prefix6 = ipxl->cfg.xlat_prefix6;
	lowest_ipv6_mtu = ipxl->cfg.lowest_ipv6_mtu;
	mutex_unlock(&ipxl->cfg_lock);

	hdr = genlmsg_put(skb, portid, seq, &ipxl_nl_family, flags,
			  IPXL_CMD_DEV_GET);
	if (!hdr)
		return -ENOBUFS;

	if (nla_put_u32(skb, IPXL_A_DEV_IFINDEX, ipxl->dev->ifindex))
		goto err;

	if (!net_eq(src_net, dev_net(ipxl->dev))) {
		id = peernet2id_alloc(src_net, dev_net(ipxl->dev), GFP_ATOMIC);
		if (id < 0) {
			ret = id;
			goto err;
		}
		if (nla_put_s32(skb, IPXL_A_DEV_NETNSID, id))
			goto err;
	}

	attr_cfg = nla_nest_start(skb, IPXL_A_DEV_CONFIG);
	if (!attr_cfg)
		goto err;

	attr_pool = nla_nest_start(skb, IPXL_A_CFG_XLAT_PREFIX6);
	if (!attr_pool)
		goto err;

	if (nla_put_in6_addr(skb, IPXL_A_POOL_PREFIX, &xlat_prefix6.addr) ||
	    nla_put_u8(skb, IPXL_A_POOL_PREFIX_LEN, xlat_prefix6.len))
		goto err;

	nla_nest_end(skb, attr_pool);

	if (nla_put_u32(skb, IPXL_A_CFG_LOWEST_IPV6_MTU, lowest_ipv6_mtu))
		goto err;

	nla_nest_end(skb, attr_cfg);
	genlmsg_end(skb, hdr);

	return 0;
err:
	genlmsg_cancel(skb, hdr);
	return ret;
}

int ipxl_nl_dev_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct ipxl_nl_info_ctx *ctx = (struct ipxl_nl_info_ctx *)info->ctx;
	struct sk_buff *reply;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, IPXL_A_DEV_IFINDEX))
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

int ipxl_nl_dev_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
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
			if (skb->len > 0)
				break;
			rcu_read_unlock();
			return ret;
		}
	}
	rcu_read_unlock();
	return skb->len;
}

static int ipxl_nl_validate_xlat_prefix6(const struct ipv6_prefix *prefix,
				  struct netlink_ext_ack *extack)
{
	struct in6_addr addr_prefix;

	if (prefix->len != 32 && prefix->len != 40 && prefix->len != 48 &&
	    prefix->len != 56 && prefix->len != 64 && prefix->len != 96) {
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "unsupported RFC 6052 prefix length: %u",
				       prefix->len);
		return -EINVAL;
	}

	ipv6_addr_prefix(&addr_prefix, &prefix->addr, prefix->len);
	if (!ipv6_addr_equal(&addr_prefix, &prefix->addr)) {
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "'%pI6c/%u' has non-zero host bits",
				       &prefix->addr, prefix->len);
		return -EINVAL;
	}

	return 0;
}

static int ipxl_nl_parse_xlat_prefix6(struct nlattr *attr, struct ipv6_prefix *xlat_prefix6,
			       struct netlink_ext_ack *extack)
{
	struct nlattr *attrs_pool[IPXL_A_POOL_MAX + 1];
	struct ipv6_prefix new_xlat_prefix6;
	int ret;

	new_xlat_prefix6 = *xlat_prefix6;

	ret = nla_parse_nested(attrs_pool, IPXL_A_POOL_MAX, attr,
			       ipxl_pool_nl_policy, extack);
	if (ret)
		return ret;

	if (!attrs_pool[IPXL_A_POOL_PREFIX] &&
	    !attrs_pool[IPXL_A_POOL_PREFIX_LEN]) {
		NL_SET_ERR_MSG_MOD(extack, "xlat-prefix6 update is empty");
		return -EINVAL;
	}

	if (attrs_pool[IPXL_A_POOL_PREFIX])
		new_xlat_prefix6.addr =
			nla_get_in6_addr(attrs_pool[IPXL_A_POOL_PREFIX]);
	if (attrs_pool[IPXL_A_POOL_PREFIX_LEN])
		new_xlat_prefix6.len = nla_get_u8(attrs_pool[IPXL_A_POOL_PREFIX_LEN]);

	ret = ipxl_nl_validate_xlat_prefix6(&new_xlat_prefix6, extack);
	if (ret) {
		if (attrs_pool[IPXL_A_POOL_PREFIX_LEN])
			NL_SET_BAD_ATTR(extack,
					attrs_pool[IPXL_A_POOL_PREFIX_LEN]);
		else
			NL_SET_BAD_ATTR(extack, attrs_pool[IPXL_A_POOL_PREFIX]);
		return ret;
	}

	*xlat_prefix6 = new_xlat_prefix6;
	return 0;
}

int ipxl_nl_dev_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct ipxl_nl_info_ctx *ctx = (struct ipxl_nl_info_ctx *)info->ctx;
	struct nlattr *attrs[IPXL_A_CFG_MAX + 1];
	struct ipv6_prefix xlat_prefix6;
	u32 lowest_ipv6_mtu;
	int ret = 0;

	if (GENL_REQ_ATTR_CHECK(info, IPXL_A_DEV_CONFIG))
		return -EINVAL;

	ret = nla_parse_nested(attrs, IPXL_A_CFG_MAX,
			       info->attrs[IPXL_A_DEV_CONFIG],
			       ipxl_cfg_nl_policy, info->extack);
	if (ret)
		return ret;

	if (!attrs[IPXL_A_CFG_XLAT_PREFIX6] && !attrs[IPXL_A_CFG_LOWEST_IPV6_MTU]) {
		NL_SET_ERR_MSG_MOD(info->extack, "config update is empty");
		return -EINVAL;
	}

	mutex_lock(&ctx->ipxl->cfg_lock);

	/* Parse and validate all requested attributes first, then apply in a
	 * separate phase. This preserves dev-set as an all-or-nothing update
	 * and avoids committing partial state if a later attribute fails.
	 */
	if (attrs[IPXL_A_CFG_XLAT_PREFIX6]) {
		xlat_prefix6 = ctx->ipxl->cfg.xlat_prefix6;
		ret = ipxl_nl_parse_xlat_prefix6(attrs[IPXL_A_CFG_XLAT_PREFIX6], &xlat_prefix6,
					  info->extack);
		if (ret)
			goto out_unlock;
	}

	if (attrs[IPXL_A_CFG_XLAT_PREFIX6])
		ctx->ipxl->cfg.xlat_prefix6 = xlat_prefix6;
	if (attrs[IPXL_A_CFG_LOWEST_IPV6_MTU]) {
		lowest_ipv6_mtu =
			nla_get_u32(attrs[IPXL_A_CFG_LOWEST_IPV6_MTU]);
		WRITE_ONCE(ctx->ipxl->cfg.lowest_ipv6_mtu, lowest_ipv6_mtu);
	}

out_unlock:
	mutex_unlock(&ctx->ipxl->cfg_lock);
	return ret;
}

/**
 * ipxl_nl_register - perform any needed registration in the netlink subsystem
 *
 * Return: 0 on success, a negative error code otherwise
 */
int __init ipxl_nl_register(void)
{
	return genl_register_family(&ipxl_nl_family);
}

/**
 * ipxl_nl_unregister - undo any module wide netlink registration
 */
void ipxl_nl_unregister(void)
{
	genl_unregister_family(&ipxl_nl_family);
}

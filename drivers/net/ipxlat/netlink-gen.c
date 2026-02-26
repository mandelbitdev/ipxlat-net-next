// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/ipxlat.yaml */
/* YNL-GEN kernel source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <net/netlink.h>
#include <net/genetlink.h>

#include "netlink-gen.h"

#include <uapi/linux/ipxl.h>

/* Common nested types */
const struct nla_policy ipxl_cfg_nl_policy[IPXL_A_CFG_COMPUTE_UDP_CSUM_ZERO + 1] = {
	[IPXL_A_CFG_POOL6] = NLA_POLICY_NESTED(ipxl_pool_nl_policy),
	[IPXL_A_CFG_POOL6791V6] = NLA_POLICY_EXACT_LEN(16),
	[IPXL_A_CFG_POOL6791V4] = { .type = NLA_BE32, },
	[IPXL_A_CFG_LOWEST_IPV6_MTU] = NLA_POLICY_MIN(NLA_U32, 1280),
	[IPXL_A_CFG_COMPUTE_UDP_CSUM_ZERO] = NLA_POLICY_MAX(NLA_U8, 1),
};

const struct nla_policy ipxl_pool_nl_policy[IPXL_A_POOL_PREFIX_LEN + 1] = {
	[IPXL_A_POOL_PREFIX] = NLA_POLICY_EXACT_LEN(16),
	[IPXL_A_POOL_PREFIX_LEN] = NLA_POLICY_MAX(NLA_U8, IPXL_POOL6_MAX_PREFIX_LEN),
};

/* IPXL_CMD_DEV_GET - do */
static const struct nla_policy ipxl_dev_get_nl_policy[IPXL_A_DEV_IFINDEX + 1] = {
	[IPXL_A_DEV_IFINDEX] = { .type = NLA_U32, },
};

/* IPXL_CMD_DEV_SET - do */
static const struct nla_policy ipxl_dev_set_nl_policy[IPXL_A_DEV_CONFIG + 1] = {
	[IPXL_A_DEV_IFINDEX] = { .type = NLA_U32, },
	[IPXL_A_DEV_CONFIG] = NLA_POLICY_NESTED(ipxl_cfg_nl_policy),
};

/* Ops table for ipxl */
static const struct genl_split_ops ipxl_nl_ops[] = {
	{
		.cmd		= IPXL_CMD_DEV_GET,
		.pre_doit	= ipxl_nl_pre_doit,
		.doit		= ipxl_nl_dev_get_doit,
		.post_doit	= ipxl_nl_post_doit,
		.policy		= ipxl_dev_get_nl_policy,
		.maxattr	= IPXL_A_DEV_IFINDEX,
		.flags		= GENL_CMD_CAP_DO,
	},
	{
		.cmd	= IPXL_CMD_DEV_GET,
		.dumpit	= ipxl_nl_dev_get_dumpit,
		.flags	= GENL_CMD_CAP_DUMP,
	},
	{
		.cmd		= IPXL_CMD_DEV_SET,
		.pre_doit	= ipxl_nl_pre_doit,
		.doit		= ipxl_nl_dev_set_doit,
		.post_doit	= ipxl_nl_post_doit,
		.policy		= ipxl_dev_set_nl_policy,
		.maxattr	= IPXL_A_DEV_CONFIG,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
};

struct genl_family ipxl_nl_family __ro_after_init = {
	.name		= IPXL_FAMILY_NAME,
	.version	= IPXL_FAMILY_VERSION,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.split_ops	= ipxl_nl_ops,
	.n_split_ops	= ARRAY_SIZE(ipxl_nl_ops),
};

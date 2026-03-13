/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/ipxlat.yaml */
/* YNL-GEN uapi header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _UAPI_LINUX_IPXL_H
#define _UAPI_LINUX_IPXL_H

#define IPXL_FAMILY_NAME	"ipxl"
#define IPXL_FAMILY_VERSION	1

#define IPXL_XLAT_PREFIX6_MAX_PREFIX_LEN	96

enum {
	IPXL_A_POOL_PREFIX = 1,
	IPXL_A_POOL_PREFIX_LEN,

	__IPXL_A_POOL_MAX,
	IPXL_A_POOL_MAX = (__IPXL_A_POOL_MAX - 1)
};

enum {
	IPXL_A_CFG_XLAT_PREFIX6 = 1,
	IPXL_A_CFG_LOWEST_IPV6_MTU,

	__IPXL_A_CFG_MAX,
	IPXL_A_CFG_MAX = (__IPXL_A_CFG_MAX - 1)
};

enum {
	IPXL_A_DEV_IFINDEX = 1,
	IPXL_A_DEV_NETNSID,
	IPXL_A_DEV_CONFIG,

	__IPXL_A_DEV_MAX,
	IPXL_A_DEV_MAX = (__IPXL_A_DEV_MAX - 1)
};

enum {
	IPXL_CMD_DEV_GET = 1,
	IPXL_CMD_DEV_SET,

	__IPXL_CMD_MAX,
	IPXL_CMD_MAX = (__IPXL_CMD_MAX - 1)
};

#endif /* _UAPI_LINUX_IPXL_H */

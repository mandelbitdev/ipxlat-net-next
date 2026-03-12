/* SPDX-License-Identifier: GPL-2.0 */
/*  IPXLAT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2026- Mandelbit, SRL
 *
 *  Author:	Alberto Leiva Popper <ydahhrk@gmail.com>
 *		Antonio Quartulli <antonio@mandelbit.com>
 *		Ralf Lici <ralf@mandelbit.com>
 */

#ifndef _NET_IPXLAT_IPXLPRIV_H_
#define _NET_IPXLAT_IPXLPRIV_H_

#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <net/gro_cells.h>

/**
 * struct ipv6_prefix - IPv6 prefix definition
 * @addr: prefix address with host bits cleared
 * @len: prefix length in bits
 */
struct ipv6_prefix {
	struct in6_addr addr;
	u8 len;
};

/**
 * struct ipxl_cfg - per-device translator configuration
 * @pool6: RFC 6052 prefix used for stateless v4<->v6 mapping
 * @lowest_ipv6_mtu: LIM threshold used by 4->6 pre-fragment planning
 */
struct ipxl_cfg {
	struct ipv6_prefix pool6;
	u32 lowest_ipv6_mtu;
};

/**
 * struct ipxl_priv - private state stored in netdev priv area
 * @dev: owning netdevice
 * @cfg: active per-device configuration (read locklessly in datapath)
 * @cfg_lock: serializes control-plane updates to @cfg
 * @gro_cells: receive-side reinjection queue used by forward path
 *
 * Datapath reads @cfg locklessly to keep per-packet cost low. Readers use
 * READ_ONCE for scalar fields that influence hot-path decisions and plain
 * loads for aggregate fields. Writers serialize updates under @cfg_lock.
 * During live reconfiguration, readers may transiently observe mixed old/new
 * values; this is an accepted tradeoff for a lightweight datapath.
 */
struct ipxl_priv {
	struct net_device *dev;
	struct ipxl_cfg cfg;
	/* serializes control-plane updates to cfg */
	struct mutex cfg_lock;
	struct gro_cells gro_cells;
};

#endif /* _NET_IPXLAT_IPXLPRIV_H_ */

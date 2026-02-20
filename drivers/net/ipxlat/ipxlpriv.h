/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_IPXLPRIV_H_
#define _NET_IPXLAT_IPXLPRIV_H_

#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <net/gro_cells.h>

#include "cfg.h"

struct ipxl_priv {
	struct net_device *dev;
	struct ipxl_cfg __rcu *cfg;
	/* Serializes cfg replacement from control plane updates. */
	struct mutex cfg_lock;
	struct gro_cells gro_cells;
};

struct ipxl_pkt_ctx {
	struct net_device *dev;
	const struct ipxl_cfg *cfg;
};

enum ipxl_action {
	IPXL_ACT_DROP = 0,
	IPXL_ACT_FWD,
	IPXL_ACT_PRE_FRAG,
	IPXL_ACT_ICMP_ERR,
};

#endif /* _NET_IPXLAT_IPXLPRIV_H_ */

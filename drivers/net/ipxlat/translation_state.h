// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_SIIT_TRANSLATION_STATE_H_
#define _NET_SIIT_TRANSLATION_STATE_H_

#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <uapi/linux/if_link.h>
#include <net/gro_cells.h>

#include "packet.h"
#include "types.h"

struct ipxl_priv {
	struct net_device *dev;
	/* Datapath readers use RCU, netlink writers serialize with cfg_lock. */
	struct ipxl_cfg __rcu *cfg;
	struct mutex cfg_lock;
	struct gro_cells gro_cells;
};

struct ipxl_pkt_ctx {
	struct net_device *dev;
	const struct ipxl_cfg *cfg;
};

enum ipxl_xlat_action {
	IPXL_XLAT_ACT_DROP = 0,
	IPXL_XLAT_ACT_FWD,
	IPXL_XLAT_ACT_PRE_FRAG,
	IPXL_XLAT_ACT_ICMP_ERR,
};

int ipxl_drop_icmp(const struct ipxl_pkt_ctx *ctx, struct sk_buff *skb,
		   __u8 type, __u8 code, __u32 info);

#endif /* _NET_SIIT_TRANSLATION_STATE_H_ */

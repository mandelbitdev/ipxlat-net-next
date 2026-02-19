// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_MAIN_H_
#define _NET_IPXLAT_MAIN_H_

#include <linux/netdevice.h>

bool ipxl_dev_is_valid(const struct net_device *dev);

#endif /* _NET_IPXLAT_MAIN_H_ */

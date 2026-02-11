// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_NETLINK_H_
#define _NET_IPXLAT_NETLINK_H_

int ipxl_nl_register(void);
void ipxl_nl_unregister(void);

#endif /* _NET_IPXLAT_NETLINK_H_ */

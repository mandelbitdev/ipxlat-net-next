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

#ifndef _NET_IPXLAT_NETLINK_H_
#define _NET_IPXLAT_NETLINK_H_

/**
 * ipxlat_nl_register - register ipxlat generic-netlink family
 *
 * Return: 0 on success, negative errno on registration failure.
 */
int ipxlat_nl_register(void);

/**
 * ipxlat_nl_unregister - unregister ipxlat generic-netlink family
 */
void ipxlat_nl_unregister(void);

#endif /* _NET_IPXLAT_NETLINK_H_ */

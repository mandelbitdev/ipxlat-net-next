/* SPDX-License-Identifier: GPL-2.0 */
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_IPXLAT_ICMP_COMPAT_H_
#define _NET_IPXLAT_ICMP_COMPAT_H_

#define icmp4_unused un.gateway
#define icmp4_datagram_length un.reserved[1]

#define ICMP_PTR_INDICATES_ERR 0
#define ICMP_BAD_LENGTH 2

#endif /* _NET_IPXLAT_ICMP_COMPAT_H_ */

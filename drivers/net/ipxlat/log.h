// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef _NET_SIIT_LOG_H_
#define _NET_SIIT_LOG_H_

#include <linux/printk.h>

#define log_debug(text, ...) pr_info("ipxlat: " text "\n", ##__VA_ARGS__)

/*
 * These should not be committed, so if you see one in uploaded code, delete it.
 */
#define log_delete(text, ...)                                       \
	pr_err("DELETE ME! %s(%d): " text "\n", __func__, __LINE__, \
	       ##__VA_ARGS__)
#define PR_DEBUG pr_err("%s:%d (%s())\n", __FILE__, __LINE__, __func__)

#endif /* _NET_SIIT_LOG_H_ */

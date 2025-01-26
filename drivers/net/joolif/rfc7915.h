// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#ifndef MOD_XLAT_RFC7915_H_
#define MOD_XLAT_RFC7915_H_

struct xlation;
struct sk_buff;

void jool_xlat(struct xlation *state, struct sk_buff *in);

#endif /* MOD_XLAT_RFC7915_H_ */

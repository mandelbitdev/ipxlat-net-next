// SPDX-License-Identifier: GPL-2.0
/*  SIIT - Stateless IP/ICMP Translation virtual device driver
 *
 *  Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
 *  Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>
 */

#include "translation_state.h"

int drop(struct xlation *state)
{
//	state->stats->rx_errors++;
//	state->stats->rx_dropped++;
	return -EINVAL;
}

int drop_icmp(struct xlation *state, __u8 type, __u8 code, __u32 info)
{
	state->result.set = true;
	state->result.type = type;
	state->result.code = code;
	state->result.info = info;
	return drop(state);
}

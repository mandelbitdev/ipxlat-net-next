#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# IPXLAT - Stateless IP/ICMP Translation virtual device driver
#
# Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
# Copyright (C) 2026- Mandelbit, SRL
#
#  Author:	Alberto Leiva Popper <ydahhrk@gmail.com>
#		Antonio Quartulli <antonio@mandelbit.com>
#		Ralf Lici <ralf@mandelbit.com>

set -o pipefail

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
source "$SCRIPT_DIR/ipxlat_lib.sh"

trap ipxl_cleanup EXIT

ipxl_setup_env

# Trigger UDP to a closed port from NS4 and capture translated ICMPv4 Port Unreachable
RET=0
ipxl_capture_pkts "$NS4" "icmp and icmp[0] == 3 and icmp[1] == 3" 1 3 \
	ip netns exec "$NS4" bash -c "echo x > /dev/udp/$IPXL_V4_REMOTE/9 || true"
check_err $? "icmp-error 4->6 not observed"
log_test "icmp-error xlate 4->6"

# Trigger UDP to a closed port from NS6 and capture translated ICMPv6 Port Unreachable
RET=0
ipxl_capture_pkts "$NS6" "icmp6 and ip6[40] == 1 and ip6[41] == 4" 1 3 \
	ip netns exec "$NS6" bash -c "echo x > /dev/udp/$IPXL_V6_NS4/9 || true"
check_err $? "icmp-error 6->4 not observed"
log_test "icmp-error xlate 6->4"

# Send oversized DF IPv4 packet and verify local ICMPv4 Fragmentation Needed emission
sysctl -w net.ipv4.conf.ipxl0.accept_local=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.ipxl0.rp_filter=0
sleep 2
RET=0
ipxl_capture_pkts "$NS4" "icmp and icmp[0] == 3 and icmp[1] == 4" 1 3 \
	ip netns exec "$NS4" bash -c \
	"ping -M \"do\" -s 1300 -c 1 -W 1 \"$IPXL_V4_REMOTE\" >/dev/null 2>&1 || test \$? -eq 1"
check_err $? "icmpv4 frag-needed emission not observed"
log_test "icmpv4 frag-needed emission"

exit "$EXIT_STATUS"

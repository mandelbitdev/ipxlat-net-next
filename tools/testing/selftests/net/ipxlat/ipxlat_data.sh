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

# Send ICMP Echo and verify we receive a reply back

RET=0
ip netns exec "$NS4" ping -c 2 -W 2 "$IPXL_V4_REMOTE"
check_err $? "ping 4->6 failed"
log_test "icmp-info 4->6"

RET=0
ip netns exec "$NS6" ping -6 -c 2 -W 2 -I "$IPXL_V6_NS6_SRC" "$IPXL_V6_NS4"
check_err $? "ping 6->4 failed"
log_test "icmp-info 6->4"

# Run a TCP data transfer over the translator path

RET=0
ipxl_run_iperf "$NS6" "$NS4" "$IPXL_V4_REMOTE" 5201 -n 256K
check_err $? "tcp 4->6 failed"
log_test "tcp 4->6"

RET=0
ipxl_run_iperf "$NS4" "$NS6" "$IPXL_V6_NS4" 5201 -B "$IPXL_V6_NS6_SRC" -n 256K
check_err $? "tcp 6->4 failed"
log_test "tcp 6->4"

# Run UDP traffic to verify UDP translation and delivery

RET=0
ipxl_run_iperf "$NS6" "$NS4" "$IPXL_V4_REMOTE" 5202 -u -b 5M -t 1
check_err $? "udp 4->6 failed"
log_test "udp 4->6"

RET=0
ipxl_run_iperf "$NS4" "$NS6" "$IPXL_V6_NS4" 5202 \
	-B "$IPXL_V6_NS6_SRC" -u -b 5M -t 1
check_err $? "udp 6->4 failed"
log_test "udp 6->4"

# Send one IPv4 UDP packet with checksum=0 and verify 4->6 translation.

RET=0
ipxl_capture_pkts "$NS6" \
	"ip6 and udp and dst host $IPXL_V6_REMOTE and dst port 5555" 1 3 \
	ip netns exec "$NS4" "$SCRIPT_DIR/ipxlat_udp4_zero_csum_send" \
	"$IPXL_NS4_ADDR" "$IPXL_V4_REMOTE" 5555
check_err $? "udp checksum-zero 4->6 failed"
log_test "udp checksum-zero 4->6"

exit "$EXIT_STATUS"

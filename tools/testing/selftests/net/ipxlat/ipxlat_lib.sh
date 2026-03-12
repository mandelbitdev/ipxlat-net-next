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

IPXLAT_TEST_DIR=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
source "$IPXLAT_TEST_DIR/../lib.sh"

KDIR=${KDIR:-$(readlink -f "$IPXLAT_TEST_DIR/../../../../../")}
YNL_CLI="$KDIR/tools/net/ynl/pyynl/cli.py"
YNL_SPEC="$KDIR/Documentation/netlink/specs/ipxlat.yaml"
IPXL_IPERF_TIMEOUT=${IPXL_IPERF_TIMEOUT:-10}

IPXL_TRANSLATOR_DEV=ipxl0
IPXL_VETH4_HOST=veth4r
IPXL_VETH4_NS=veth4n
IPXL_VETH6_HOST=veth6r
IPXL_VETH6_NS=veth6n

IPXL_POOL6_PREFIX=2001:db8:100::
IPXL_POOL6_LEN=40
IPXL_POOL6_HEX=20010db8010000000000000000000000
IPXL_LOWEST_IPV6_MTU=1280

IPXL_HOST4_ADDR=198.51.100.1
IPXL_HOST6_ADDR=2001:db8:1::1

IPXL_NS4_ADDR=198.51.100.2
IPXL_NS6_ADDR=2001:db8:1::2
export IPXL_V4_REMOTE=192.0.2.33

IPXL_V6_REMOTE=2001:db8:1c0:2:21::
IPXL_V6_NS4=2001:db8:1c6:3364:2::
IPXL_V6_NS6_SRC=2001:db8:1c0:2:2::
IPXL_POOL6791V4=$IPXL_HOST4_ADDR

NS4=""
NS6=""

ipxl_ynl()
{
	python3 "$YNL_CLI" --spec "$YNL_SPEC" "$@"
}

ipxl_build_dev_set_json()
{
	local ifindex="$1"

	jq -cn \
		--argjson ifindex "$ifindex" \
		--arg prefix "$IPXL_POOL6_HEX" \
		--argjson prefix_len "$IPXL_POOL6_LEN" \
		--arg pool6791v4 "$IPXL_POOL6791V4" \
		--argjson lowest_ipv6_mtu "$IPXL_LOWEST_IPV6_MTU" \
		'{
			ifindex: $ifindex,
			config: {
				pool6: {prefix: $prefix, "prefix-len": $prefix_len},
				pool6791v4: $pool6791v4,
				"lowest-ipv6-mtu": $lowest_ipv6_mtu
			}
		}'
}

ipxl_require_root()
{
	if [[ $(id -u) -ne 0 ]]; then
		echo "ipxlat selftests need root; skipping"
		exit "$ksft_skip"
	fi
}

ipxl_require_tools()
{
	if [[ ! -f "$YNL_CLI" || ! -f "$YNL_SPEC" ]]; then
		log_test_skip "ipxlat netlink spec/ynl not found"
		exit "$ksft_skip"
	fi

	for tool in ip python3 ping iperf3 tcpdump timeout jq; do
		require_command "$tool"
	done
}

ipxl_cleanup()
{
	cleanup_ns "${NS4:-}" "${NS6:-}" || true
	ip link del "$IPXL_TRANSLATOR_DEV" 2>/dev/null || true
	ip link del "$IPXL_VETH4_HOST" 2>/dev/null || true
	ip link del "$IPXL_VETH6_HOST" 2>/dev/null || true
}

# Test topology:
#
# host namespace:
#   - owns ipxlat dev `ipxl0`
#   - has veth peers `veth4r` and `veth6r`
#   - routes IPv4 test prefix (192.0.2.0/24) to ipxl0 (v4 network steering rule)
#   - routes pool6 prefix (2001:db8:100::/40) out to NS6 side
#   - routes mapped NS4 IPv6 identity (2001:db8:1c6:3364:2::/128) to ipxl0
#     so NS6->NS4 traffic enters 6->4 translation
#
# NS4:
#   - IPv4-only endpoint: 198.51.100.2/24 on veth4n
#   - default route via host 198.51.100.1 (veth4r)
#   - sends traffic to 192.0.2.33 (translated by ipxl0 to IPv6)
#
# NS6:
#   - IPv6 endpoint: 2001:db8:1::2/64 on veth6n
#   - also owns mapped addresses used by tests:
#       2001:db8:1c0:2:21::  (maps to 192.0.2.33)
#       2001:db8:1c0:2:2::   (maps to 192.0.2.2, used as explicit src since we have multiple v6 addresses)
#   - route to mapped NS4 IPv6 address is pinned via host:
#       2001:db8:1c6:3364:2::/128
#     This keeps the 6->4 test path deterministic.
#
# ipxlat config under test:
#   - pool6 = 2001:db8:100::/40
#   - pool6791v4 = 198.51.100.1
#   - lowest-ipv6-mtu = 1280
ipxl_configure_topology()
{
	local ifindex
	local dev_set_json

	if ! ip link add "$IPXL_TRANSLATOR_DEV" type ipxlat; then
		echo "ipxlat link kind unavailable; skipping"
		exit "$ksft_skip"
	fi
	ip link set "$IPXL_TRANSLATOR_DEV" up
	ifindex=$(cat /sys/class/net/"$IPXL_TRANSLATOR_DEV"/ifindex)
	dev_set_json=$(ipxl_build_dev_set_json "$ifindex")

	if ! ipxl_ynl --do dev-set --json "$dev_set_json" >/dev/null; then
		echo "ipxlat dev-set failed"
		exit "$ksft_fail"
	fi

	setup_ns NS4 NS6 || exit "$ksft_skip"

	ip link add "$IPXL_VETH4_HOST" type veth peer name "$IPXL_VETH4_NS"
	ip link add "$IPXL_VETH6_HOST" type veth peer name "$IPXL_VETH6_NS"
	ip link set "$IPXL_VETH4_NS" netns "$NS4"
	ip link set "$IPXL_VETH6_NS" netns "$NS6"

	ip addr add "$IPXL_HOST4_ADDR/24" dev "$IPXL_VETH4_HOST"
	ip -6 addr add "$IPXL_HOST6_ADDR/64" dev "$IPXL_VETH6_HOST"
	ip link set "$IPXL_VETH4_HOST" up
	ip link set "$IPXL_VETH6_HOST" up

	ip netns exec "$NS4" ip addr add "$IPXL_NS4_ADDR/24" dev "$IPXL_VETH4_NS"
	ip netns exec "$NS4" ip link set "$IPXL_VETH4_NS" up
	ip netns exec "$NS4" ip route add default via "$IPXL_HOST4_ADDR"

	ip netns exec "$NS6" ip -6 addr add "$IPXL_NS6_ADDR/64" dev "$IPXL_VETH6_NS"
	ip netns exec "$NS6" ip -6 addr add "$IPXL_V6_REMOTE/128" dev "$IPXL_VETH6_NS"
	ip netns exec "$NS6" ip -6 addr add "$IPXL_V6_NS6_SRC/128" dev "$IPXL_VETH6_NS"
	ip netns exec "$NS6" ip link set "$IPXL_VETH6_NS" up
	ip netns exec "$NS6" ip -6 route add default via "$IPXL_HOST6_ADDR"
	ip netns exec "$NS6" ip -6 route replace "$IPXL_V6_NS4/128" \
		via "$IPXL_HOST6_ADDR"
	sleep 2

	sysctl -qw net.ipv4.ip_forward=1
	sysctl -qw net.ipv6.conf.all.forwarding=1

	# 4->6 steering rule
	ip route replace 192.0.2.0/24 dev "$IPXL_TRANSLATOR_DEV"
	# Post-translation egress: IPv6 destinations in pool6 leave toward NS6.
	ip -6 route replace "$IPXL_POOL6_PREFIX/$IPXL_POOL6_LEN" dev "$IPXL_VETH6_HOST"
	# 6->4 steering rule
	ip -6 route replace "$IPXL_V6_NS4/128" dev "$IPXL_TRANSLATOR_DEV"

	ip link set "$IPXL_VETH6_HOST" mtu 1280
	ip netns exec "$NS6" ip link set "$IPXL_VETH6_NS" mtu 1280
}

ipxl_setup_env()
{
	ipxl_require_root
	ipxl_require_tools
	ipxl_cleanup

	ipxl_configure_topology
}

ipxl_run_iperf()
{
	local srv_ns="$1"
	local cli_ns="$2"
	local dst="$3"
	local port="$4"
	local -a args=()
	local client_rc
	local server_rc
	local spid
	local idx

	for ((idx = 5; idx <= $#; idx++)); do
		args+=("${!idx}")
	done

	ip netns exec "$srv_ns" timeout "$IPXL_IPERF_TIMEOUT" \
		iperf3 -s -1 -p "$port" &
	spid=$!
	sleep 0.2

	ip netns exec "$cli_ns" timeout "$IPXL_IPERF_TIMEOUT" \
		iperf3 -c "$dst" -p "$port" "${args[@]}"

	client_rc=$?
	if [[ $client_rc -ne 0 ]]; then
		kill "$spid" >/dev/null 2>&1 || true
	fi

	wait "$spid" >/dev/null 2>&1
	server_rc=$?

	((client_rc != 0)) && return "$client_rc"
	return "$server_rc"
}

ipxl_capture_pkts()
{
	local ns="$1"
	local filter="$2"
	local expect_pkts="$3"
	local timeout_s="$4"
	local cap_goal
	local cap_pid
	local rc
	local trigger_rc

	shift 4

	cap_goal=1
	[[ $expect_pkts -gt 0 ]] && cap_goal=$expect_pkts

	ip netns exec "$ns" timeout "$timeout_s" tcpdump -nni any -c "$cap_goal" \
		"$filter" >/dev/null 2>&1 &
	cap_pid=$!
	sleep 0.2

	"$@"
	trigger_rc=$?
	wait "$cap_pid" >/dev/null 2>&1
	rc=$?

	if [[ $trigger_rc -ne 0 ]]; then
		return "$trigger_rc"
	fi

	if [[ $expect_pkts -eq 0 ]]; then
		[[ $rc -eq 124 ]]
	else
		[[ $rc -eq 0 ]]
	fi
}

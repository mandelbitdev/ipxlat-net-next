# SPDX-License-Identifier: GPL-2.0
#
# IPXLAT - Stateless IP/ICMP Translation (SIIT) virtual device driver
#
# Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
# Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>

obj-$(CONFIG_IPXLAT) := ipxlat.o

ipxlat-objs += main.o
ipxlat-objs += rfc7915.o
ipxlat-objs += address.o
ipxlat-objs += ipv6_hdr_iterator.o
ipxlat-objs += packet.o
ipxlat-objs += translation_state.o

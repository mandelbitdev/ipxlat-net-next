# SPDX-License-Identifier: GPL-2.0
#
# IPXLAT - Stateless IP/ICMP Translation (SIIT) virtual device driver
#
# Copyright (C) 2024- Alberto Leiva Popper <ydahhrk@gmail.com>
# Copyright (C) 2025- Antonio Quartulli <antonio@mandelbit.com>

obj-$(CONFIG_IPXLAT) := ipxlat.o

ipxlat-objs += main.o
ipxlat-objs += dispatch.o
ipxlat-objs += translate_46.o
ipxlat-objs += translate_64.o
ipxlat-objs += icmp_46.o
ipxlat-objs += icmp_64.o
ipxlat-objs += transport.o
ipxlat-objs += address.o
ipxlat-objs += packet.o
ipxlat-objs += netlink.o
ipxlat-objs += netlink-gen.o

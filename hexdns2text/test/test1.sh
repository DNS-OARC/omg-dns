#!/bin/sh -xe
#
# Author Jerry Lundström <jerry@dns-oarc.net>
# Copyright (c) 2017, OARC, Inc.
# All rights reserved.
#
# This file is part of omg-dns.
#
# omg-dns is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# omg-dns is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with omg-dns.  If not, see <http://www.gnu.org/licenses/>.

../hexdns2text \
  50f40100000100000000000006676f6f676c6503636f6d0000010001 \
  50f48180000100010000000006676f6f676c6503636f6d0000010001c00c00010001000000150004acd916ae \
  70f78180000100010000000006676f6f676c6503636f6d0000060001c00c000600010000003b0026036e7333c00c09646e732d61646d696ec00c08a155200000038400000384000007080000003c \
  > test1.out

diff test1.out test1.gold

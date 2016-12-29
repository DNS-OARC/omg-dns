# Author Jerry Lundström <jerry@dns-oarc.net>
# Copyright (c) 2016, OARC, Inc.
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

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = omg_dns.c omg_dns.h

SUBDIRS = test

AM_CFLAGS = -Wall -I$(srcdir)

bin_PROGRAMS = hexdns2text

hexdns2text_SOURCES = hexdns2text.c omg_dns.c omg_dns.h

hexdns2text.c: omg_dns.h

omg_dns.c: $(top_srcdir)/../omg_dns.c omg_dns.h
	cp "$(top_srcdir)/../omg_dns.c" "$(srcdir)"

omg_dns.h: $(top_srcdir)/../omg_dns.h
	cp "$(top_srcdir)/../omg_dns.h" "$(srcdir)"

test: check

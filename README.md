# omg-dns

[![Build Status](https://travis-ci.org/DNS-OARC/omg-dns.svg?branch=develop)](https://travis-ci.org/DNS-OARC/omg-dns) [![Coverity Scan Build Status](https://scan.coverity.com/projects/11504/badge.svg)](https://scan.coverity.com/projects/dns-oarc-omg-dns)

Helper library for parsing valid/invalid/broken/malformed DNS packets

## About

This is a helper library intended to be included within other projects
repositories as a submodule to help them parse DNS packets.  It will parse
as much as possible and will indicate where and what failed if any.

Supported RFCs:
- todo

## Usage

Here is a short example how to use this library.

```c
#include "config.h"
#include "omg-dns/omg_dns.h"
#include <stdio.h>

static int label_callback(const omg_dns_label_t* label, void* context) {
    ...

    return OMG_DNS_OK;
}

static int rr_callback(int ret, const omg_dns_rr_t* rr, void* context) {
    ...

    return OMG_DNS_OK;
}

int main(void) {
    omg_dns_t dns = OMG_DNS_T_INIT;
    uint8_t * data;
    size_t length;

    ...
    Read DNS packet and set data and length
    ...

    omg_dns_set_rr_callback(&dns, rr_callback, 0;
    omg_dns_set_label_callback(&dns, label_callback, 0;
    ret = omg_dns_parse(&dns, data, length);

    if (omg_dns_have_id(&dns))
        printf("id: %u\n", omg_dns_id(&dns));

    return 0;
}
```

### git submodule

```shell
git submodule init
git submodule add https://github.com/DNS-OARC/omg-dns.git src/omg-dns
```

## Author(s)

Jerry Lundström <jerry@dns-oarc.net>

## Copyright

Copyright (c) 2017, OARC, Inc.
All rights reserved.

This file is part of omg-dns.

omg-dns is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

omg-dns is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with omg-dns.  If not, see <http://www.gnu.org/licenses/>.

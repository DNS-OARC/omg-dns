# omg-dns

Helper library for parsing valid/invalid/broken/malformed DNS packets

## About

This is a helper library intended to be included within other projects
repositories as a submodule to help them parse DNS packets.  It will parse
as much as possible and will indicate where and what failed if any.

Supported RFCs:
- todo

## Usage

Here is a short example how to use this library, for a more complete program
check `hexdns2text/hexdns2text.c`.

```c
#include "omg-dns/omg_dns.h"
#include <stdio.h>

struct context {
    size_t num_rr;
    size_t num_label;
};

static int label_callback(const omg_dns_label_t* label, void* vp) {
    struct context* context = (struct context*)vp;

    printf("  label %lu:\n", context->num_label++);
    if (omg_dns_label_is_end(label))
        printf("    end: yes\n");
    else if (!omg_dns_label_is_complete(label))
        printf("    incomplete: yes\n");
    else if (omg_dns_label_have_offset(label))
        printf("    offset: %d\n", omg_dns_label_offset(label));
    else if (omg_dns_label_have_extension_bits(label))
        printf("    extension_bits: %02x\n", omg_dns_label_extension_bits(label));

    return OMG_DNS_OK;
}

static int rr_callback(int ret, const omg_dns_rr_t* rr, void* vp) {
    struct context* context = (struct context*)vp;

    printf("  rr %lu:\n", context->num_rr++);
    printf("    question: %s\n", omg_dns_rr_is_question(rr) ? "yes" : "no");
    if (omg_dns_rr_have_type(rr))
        printf("    type: %u\n", omg_dns_rr_type(rr));

    return OMG_DNS_OK;
}

int main(void) {
    omg_dns_t dns = OMG_DNS_T_INIT;
    struct context context = { 0, 0 };
    uint8_t packet[] = { ... raw dns packet as byte array ... };

    omg_dns_set_rr_callback(&dns, rr_callback, (void*)&context);
    omg_dns_set_label_callback(&dns, label_callback, (void*)&context);
    omg_dns_parse(&dns, packet, sizeof(packet));

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

### Makefile.am

```m4
program_SOURCES += omg-dns/omg_dns.c
dist_program_SOURCES += omg-dns/omg_dns.h
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

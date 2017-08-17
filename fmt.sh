#!/bin/sh

clang-format-4.0 \
    -style=file \
    -i \
    omg_dns.c \
    omg_dns.h \
    hexdns2text/hexdns2text.c

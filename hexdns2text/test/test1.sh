#!/bin/sh -xe

../hexdns2text \
  50f40100000100000000000006676f6f676c6503636f6d0000010001 \
  50f48180000100010000000006676f6f676c6503636f6d0000010001c00c00010001000000150004acd916ae \
  70f78180000100010000000006676f6f676c6503636f6d0000060001c00c000600010000003b0026036e7333c00c09646e732d61646d696ec00c08a155200000038400000384000007080000003c \
  > test1.out

diff test1.out test1.gold
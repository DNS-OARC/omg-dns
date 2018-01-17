/*
 * Author Jerry Lundström <jerry@dns-oarc.net>
 * Copyright (c) 2017, OARC, Inc.
 * All rights reserved.
 *
 * This file is part of omg-dns.
 *
 * omg-dns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * omg-dns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with omg-dns.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __omg_dns_h
#define __omg_dns_h

#include <netinet/in.h>
#if OMG_DNS_ENABLE_ASSERT
#include <assert.h>
#define omg_dns_assert(x) assert(x)
#else
#define omg_dns_assert(x)
#endif

/* clang-format off */

#define OMG_DNS_VERSION_STR     "1.0.0"
#define OMG_DNS_VERSION_MAJOR   1
#define OMG_DNS_VERSION_MINOR   0
#define OMG_DNS_VERSION_PATCH   0

#define OMG_DNS_OK              0
#define OMG_DNS_EINVAL          1
#define OMG_DNS_EINCOMP         2
#define OMG_DNS_ENOMEM          3
#define OMG_DNS_EOVERRUN        4

/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

const char* omg_dns_version_str(void);
int         omg_dns_version_major(void);
int         omg_dns_version_minor(void);
int         omg_dns_version_patch(void);

/* clang-format off */
#define OMG_DNS_LABEL_T_INIT { \
    0, \
    0, \
    0,0,0,0, 0, \
    0, 0, 0, 0 \
}
/* clang-format on */

typedef struct omg_dns_label omg_dns_label_t;
struct omg_dns_label {
    size_t _offset;

    unsigned short is_end : 1;

    unsigned short have_length : 1;
    unsigned short have_offset : 1;
    unsigned short have_extension_bits : 1;
    unsigned short have_dn : 1;

    unsigned short is_complete : 1;

    uint8_t        length;
    uint16_t       offset;
    unsigned short extension_bits : 2;
    size_t         dn_offset;
};

int omg_dns_label_is_end(const omg_dns_label_t* label);
int omg_dns_label_have_length(const omg_dns_label_t* label);
int omg_dns_label_have_offset(const omg_dns_label_t* label);
int omg_dns_label_have_extension_bits(const omg_dns_label_t* label);
int omg_dns_label_have_dn(const omg_dns_label_t* label);
int omg_dns_label_is_complete(const omg_dns_label_t* label);

uint8_t omg_dns_label_length(const omg_dns_label_t* label);
uint16_t omg_dns_label_offset(const omg_dns_label_t* label);
unsigned short omg_dns_label_extension_bits(const omg_dns_label_t* label);
size_t omg_dns_label_dn_offset(const omg_dns_label_t* label);

typedef int (*omg_dns_label_callback_t)(const omg_dns_label_t* label, void* context);

/* clang-format off */
#define OMG_DNS_RR_T_INIT { \
    0, \
    0,0, \
    0, \
    0, \
    0,0,0,0,0,0,0, \
    0,0, \
    0, \
    0,0,0,0,0,0,0,0, \
}
/* clang-format on */

typedef struct omg_dns_rr omg_dns_rr_t;
struct omg_dns_rr {
    size_t _offset;

    omg_dns_label_callback_t label_callback;
    void*                    label_callback_context;

    unsigned short is_question : 1;

    unsigned short have_labels : 1;

    unsigned short have_type : 1;
    unsigned short have_class : 1;
    unsigned short have_ttl : 1;
    unsigned short have_rdlength : 1;
    unsigned short have_rdata : 1;
    unsigned short have_rdata_labels : 1;
    unsigned short have_padding : 1;

    unsigned short is_complete : 1;
    size_t         bytes_parsed;

    size_t labels;

    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    size_t   rdata_offset;
    size_t   rdata_labels;
    size_t   padding_offset;
    size_t   padding_length;
};

omg_dns_label_callback_t omg_dns_rr_label_callback(const omg_dns_rr_t* rr);
void* omg_dns_rr_label_callback_context(const omg_dns_rr_t* rr);
void omg_dns_rr_set_label_callback(omg_dns_rr_t* rr, omg_dns_label_callback_t label_callback, void* label_callback_context);

int omg_dns_rr_is_question(const omg_dns_rr_t* rr);
int omg_dns_rr_have_labels(const omg_dns_rr_t* rr);
int omg_dns_rr_have_type(const omg_dns_rr_t* rr);
int omg_dns_rr_have_class(const omg_dns_rr_t* rr);
int omg_dns_rr_have_ttl(const omg_dns_rr_t* rr);
int omg_dns_rr_have_rdlength(const omg_dns_rr_t* rr);
int omg_dns_rr_have_rdata(const omg_dns_rr_t* rr);
int omg_dns_rr_have_rdata_labels(const omg_dns_rr_t* rr);
int omg_dns_rr_have_padding(const omg_dns_rr_t* rr);
int omg_dns_rr_is_complete(const omg_dns_rr_t* rr);

size_t omg_dns_rr_bytes_parsed(const omg_dns_rr_t* rr);

size_t omg_dns_rr_labels(const omg_dns_rr_t* rr);
uint16_t omg_dns_rr_type(const omg_dns_rr_t* rr);
uint16_t omg_dns_rr_class(const omg_dns_rr_t* rr);
uint32_t omg_dns_rr_ttl(const omg_dns_rr_t* rr);
uint16_t omg_dns_rr_rdlength(const omg_dns_rr_t* rr);
size_t omg_dns_rr_rdata_offset(const omg_dns_rr_t* rr);
size_t omg_dns_rr_rdata_labels(const omg_dns_rr_t* rr);
size_t omg_dns_rr_padding_offset(const omg_dns_rr_t* rr);
size_t omg_dns_rr_padding_length(const omg_dns_rr_t* rr);
size_t omg_dns_rr_num_rdata_labels(const omg_dns_rr_t* rr);

typedef int (*omg_dns_rr_callback_t)(int ret, const omg_dns_rr_t* rr, void* context);

/* clang-format off */
#define OMG_DNS_T_INIT { \
    0,0, 0,0, \
    0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0, 0,0,0,0, 0, \
    0,0,0,0, \
    0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0 \
}
/* clang-format on */

typedef struct omg_dns omg_dns_t;
struct omg_dns {
    omg_dns_label_callback_t label_callback;
    void*                    label_callback_context;

    omg_dns_rr_callback_t rr_callback;
    void*                 rr_callback_context;

    unsigned short have_id : 1;

    unsigned short have_qr : 1;
    unsigned short have_opcode : 1;
    unsigned short have_aa : 1;
    unsigned short have_tc : 1;
    unsigned short have_rd : 1;

    unsigned short have_ra : 1;
    unsigned short have_z : 1;
    unsigned short have_ad : 1;
    unsigned short have_cd : 1;
    unsigned short have_rcode : 1;

    unsigned short have_qdcount : 1;
    unsigned short have_ancount : 1;
    unsigned short have_nscount : 1;
    unsigned short have_arcount : 1;

    unsigned short have_questions : 1;
    unsigned short have_answers : 1;
    unsigned short have_authorities : 1;
    unsigned short have_additionals : 1;

    unsigned short have_padding : 1;

    unsigned short have_header : 1;
    unsigned short have_body : 1;
    unsigned short is_complete : 1;
    size_t         bytes_parsed;

    uint16_t id;

    unsigned short qr : 1;
    unsigned short opcode : 4;
    unsigned short aa : 1;
    unsigned short tc : 1;
    unsigned short rd : 1;

    unsigned short ra : 1;
    unsigned short z : 1;
    unsigned short ad : 1;
    unsigned short cd : 1;
    unsigned short rcode : 4;

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    size_t questions;
    size_t answers;
    size_t authorities;
    size_t additionals;

    size_t padding_offset;
    size_t padding_length;
};

omg_dns_label_callback_t omg_dns_label_callback(const omg_dns_t* dns);
void* omg_dns_label_callback_context(const omg_dns_t* dns);
void omg_dns_set_label_callback(omg_dns_t* dns, omg_dns_label_callback_t label_callback, void* label_callback_context);

omg_dns_rr_callback_t omg_dns_rr_callback(const omg_dns_t* dns);
void* omg_dns_rr_callback_context(const omg_dns_t* dns);
void omg_dns_set_rr_callback(omg_dns_t* dns, omg_dns_rr_callback_t rr_callback, void* rr_callback_context);

int omg_dns_have_id(const omg_dns_t* dns);
int omg_dns_have_qr(const omg_dns_t* dns);
int omg_dns_have_opcode(const omg_dns_t* dns);
int omg_dns_have_aa(const omg_dns_t* dns);
int omg_dns_have_tc(const omg_dns_t* dns);
int omg_dns_have_rd(const omg_dns_t* dns);
int omg_dns_have_ra(const omg_dns_t* dns);
int omg_dns_have_z(const omg_dns_t* dns);
int omg_dns_have_ad(const omg_dns_t* dns);
int omg_dns_have_cd(const omg_dns_t* dns);
int omg_dns_have_rcode(const omg_dns_t* dns);
int omg_dns_have_qdcount(const omg_dns_t* dns);
int omg_dns_have_ancount(const omg_dns_t* dns);
int omg_dns_have_nscount(const omg_dns_t* dns);
int omg_dns_have_arcount(const omg_dns_t* dns);
int omg_dns_have_questions(const omg_dns_t* dns);
int omg_dns_have_answers(const omg_dns_t* dns);
int omg_dns_have_authorities(const omg_dns_t* dns);
int omg_dns_have_additionals(const omg_dns_t* dns);
int omg_dns_have_padding(const omg_dns_t* dns);
int omg_dns_have_header(const omg_dns_t* dns);
int omg_dns_have_body(const omg_dns_t* dns);
int omg_dns_is_complete(const omg_dns_t* dns);

size_t omg_dns_bytes_parsed(const omg_dns_t* dns);

uint16_t omg_dns_id(const omg_dns_t* dns);
int omg_dns_qr(const omg_dns_t* dns);
int omg_dns_opcode(const omg_dns_t* dns);
int omg_dns_aa(const omg_dns_t* dns);
int omg_dns_tc(const omg_dns_t* dns);
int omg_dns_rd(const omg_dns_t* dns);
int omg_dns_ra(const omg_dns_t* dns);
int omg_dns_z(const omg_dns_t* dns);
int omg_dns_ad(const omg_dns_t* dns);
int omg_dns_cd(const omg_dns_t* dns);
int omg_dns_rcode(const omg_dns_t* dns);
uint16_t omg_dns_qdcount(const omg_dns_t* dns);
uint16_t omg_dns_ancount(const omg_dns_t* dns);
uint16_t omg_dns_nscount(const omg_dns_t* dns);
uint16_t omg_dns_arcount(const omg_dns_t* dns);
size_t omg_dns_questions(const omg_dns_t* dns);
size_t omg_dns_answers(const omg_dns_t* dns);
size_t omg_dns_authorities(const omg_dns_t* dns);
size_t omg_dns_additionals(const omg_dns_t* dns);
size_t omg_dns_padding_offset(const omg_dns_t* dns);
size_t omg_dns_padding_length(const omg_dns_t* dns);

int omg_dns_parse_header(omg_dns_t* dns, const uint8_t* buffer, size_t length);
int omg_dns_parse_body(omg_dns_t* dns, const uint8_t* buffer, size_t length);
int omg_dns_parse(omg_dns_t* dns, const uint8_t* buffer, size_t length);
int omg_dns_parse_rr(omg_dns_rr_t* rr, const uint8_t* buffer, size_t length);

#ifdef __cplusplus
}
#endif

/*
 * 2016-12-09 https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
 */

#define OMG_DNS_CLASS_IN 1
#define OMG_DNS_CLASS_CH 3
#define OMG_DNS_CLASS_HS 4
#define OMG_DNS_CLASS_NONE 254
#define OMG_DNS_CLASS_ANY 255

#define OMG_DNS_TYPE_A 1
#define OMG_DNS_TYPE_NS 2
#define OMG_DNS_TYPE_MD 3
#define OMG_DNS_TYPE_MF 4
#define OMG_DNS_TYPE_CNAME 5
#define OMG_DNS_TYPE_SOA 6
#define OMG_DNS_TYPE_MB 7
#define OMG_DNS_TYPE_MG 8
#define OMG_DNS_TYPE_MR 9
#define OMG_DNS_TYPE_NULL 10
#define OMG_DNS_TYPE_WKS 11
#define OMG_DNS_TYPE_PTR 12
#define OMG_DNS_TYPE_HINFO 13
#define OMG_DNS_TYPE_MINFO 14
#define OMG_DNS_TYPE_MX 15
#define OMG_DNS_TYPE_TXT 16
#define OMG_DNS_TYPE_RP 17
#define OMG_DNS_TYPE_AFSDB 18
#define OMG_DNS_TYPE_X25 19
#define OMG_DNS_TYPE_ISDN 20
#define OMG_DNS_TYPE_RT 21
#define OMG_DNS_TYPE_NSAP 22
#define OMG_DNS_TYPE_NSAP_PTR 23
#define OMG_DNS_TYPE_SIG 24
#define OMG_DNS_TYPE_KEY 25
#define OMG_DNS_TYPE_PX 26
#define OMG_DNS_TYPE_GPOS 27
#define OMG_DNS_TYPE_AAAA 28
#define OMG_DNS_TYPE_LOC 29
#define OMG_DNS_TYPE_NXT 30
#define OMG_DNS_TYPE_EID 31
#define OMG_DNS_TYPE_NIMLOC 32
#define OMG_DNS_TYPE_SRV 33
#define OMG_DNS_TYPE_ATMA 34
#define OMG_DNS_TYPE_NAPTR 35
#define OMG_DNS_TYPE_KX 36
#define OMG_DNS_TYPE_CERT 37
#define OMG_DNS_TYPE_A6 38
#define OMG_DNS_TYPE_DNAME 39
#define OMG_DNS_TYPE_SINK 40
#define OMG_DNS_TYPE_OPT 41
#define OMG_DNS_TYPE_APL 42
#define OMG_DNS_TYPE_DS 43
#define OMG_DNS_TYPE_SSHFP 44
#define OMG_DNS_TYPE_IPSECKEY 45
#define OMG_DNS_TYPE_RRSIG 46
#define OMG_DNS_TYPE_NSEC 47
#define OMG_DNS_TYPE_DNSKEY 48
#define OMG_DNS_TYPE_DHCID 49
#define OMG_DNS_TYPE_NSEC3 50
#define OMG_DNS_TYPE_NSEC3PARAM 51
#define OMG_DNS_TYPE_TLSA 52
#define OMG_DNS_TYPE_SMIMEA 53
#define OMG_DNS_TYPE_HIP 55
#define OMG_DNS_TYPE_NINFO 56
#define OMG_DNS_TYPE_RKEY 57
#define OMG_DNS_TYPE_TALINK 58
#define OMG_DNS_TYPE_CDS 59
#define OMG_DNS_TYPE_CDNSKEY 60
#define OMG_DNS_TYPE_OPENPGPKEY 61
#define OMG_DNS_TYPE_CSYNC 62
#define OMG_DNS_TYPE_SPF 99
#define OMG_DNS_TYPE_UINFO 100
#define OMG_DNS_TYPE_UID 101
#define OMG_DNS_TYPE_GID 102
#define OMG_DNS_TYPE_UNSPEC 103
#define OMG_DNS_TYPE_NID 104
#define OMG_DNS_TYPE_L32 105
#define OMG_DNS_TYPE_L64 106
#define OMG_DNS_TYPE_LP 107
#define OMG_DNS_TYPE_EUI48 108
#define OMG_DNS_TYPE_EUI64 109
#define OMG_DNS_TYPE_TKEY 249
#define OMG_DNS_TYPE_TSIG 250
#define OMG_DNS_TYPE_IXFR 251
#define OMG_DNS_TYPE_AXFR 252
#define OMG_DNS_TYPE_MAILB 253
#define OMG_DNS_TYPE_MAILA 254
#define OMG_DNS_TYPE_ANY 255
#define OMG_DNS_TYPE_URI 256
#define OMG_DNS_TYPE_CAA 257
#define OMG_DNS_TYPE_AVC 258
#define OMG_DNS_TYPE_TA 32768
#define OMG_DNS_TYPE_DLV 32769

#define OMG_DNS_OPCODE_QUERY 0
#define OMG_DNS_OPCODE_IQUERY 1
#define OMG_DNS_OPCODE_STATUS 2
#define OMG_DNS_OPCODE_NOTIFY 4
#define OMG_DNS_OPCODE_UPDATE 5

#define OMG_DNS_RCODE_NOERROR 0
#define OMG_DNS_RCODE_FORMERR 1
#define OMG_DNS_RCODE_SERVFAIL 2
#define OMG_DNS_RCODE_NXDOMAIN 3
#define OMG_DNS_RCODE_NOTIMP 4
#define OMG_DNS_RCODE_REFUSED 5
#define OMG_DNS_RCODE_YXDOMAIN 6
#define OMG_DNS_RCODE_YXRRSET 7
#define OMG_DNS_RCODE_NXRRSET 8
#define OMG_DNS_RCODE_NOTAUTH 9
#define OMG_DNS_RCODE_NOTZONE 10
#define OMG_DNS_RCODE_BADVERS 16
#define OMG_DNS_RCODE_BADSIG 16
#define OMG_DNS_RCODE_BADKEY 17
#define OMG_DNS_RCODE_BADTIME 18
#define OMG_DNS_RCODE_BADMODE 19
#define OMG_DNS_RCODE_BADNAME 20
#define OMG_DNS_RCODE_BADALG 21
#define OMG_DNS_RCODE_BADTRUNC 22
#define OMG_DNS_RCODE_BADCOOKIE 23

#define OMG_DNS_AFSDB_SUBTYPE_AFS3LOCSRV 1
#define OMG_DNS_AFSDB_SUBTYPE_DCENCA_ROOT 2

#define OMG_DNS_DHCID_TYPE_1OCTET 0
#define OMG_DNS_DHCID_TYPE_DATAOCTET 1
#define OMG_DNS_DHCID_TYPE_CLIENT_DUID 2

#define OMG_DNS_EDNS0_OPT_LLQ 1
#define OMG_DNS_EDNS0_OPT_UL 2
#define OMG_DNS_EDNS0_OPT_NSID 3
#define OMG_DNS_EDNS0_OPT_DAU 5
#define OMG_DNS_EDNS0_OPT_DHU 6
#define OMG_DNS_EDNS0_OPT_N3U 7
#define OMG_DNS_EDNS0_OPT_CLIENT_SUBNET 8
#define OMG_DNS_EDNS0_OPT_EXPIRE 9
#define OMG_DNS_EDNS0_OPT_COOKIE 10
#define OMG_DNS_EDNS0_OPT_TCP_KEEPALIVE 11
#define OMG_DNS_EDNS0_OPT_PADDING 12
#define OMG_DNS_EDNS0_OPT_CHAIN 13
#define OMG_DNS_EDNS0_OPT_DEVICEID 26946

#endif /* __omg_dns_h */

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

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include "omg_dns.h"

/*
 * Version
 */

static const char* _version = OMG_DNS_VERSION_STR;
inline const char* omg_dns_version_str(void) {
    return _version;
}

inline int omg_dns_version_major(void) {
    return OMG_DNS_VERSION_MAJOR;
}

inline int omg_dns_version_minor(void) {
    return OMG_DNS_VERSION_MINOR;
}

inline int omg_dns_version_patch(void) {
    return OMG_DNS_VERSION_PATCH;
}

/*
 * Buffer inlines and macros
 */

#define need8(v, p, l) \
    if (l < 1) { \
        return OMG_DNS_EINCOMP; \
    } \
    v = *p; \
    p += 1; \
    l -= 1

#define need16(v, p, l) \
    if (l < 2) { \
        return OMG_DNS_EINCOMP; \
    } \
    v = ( *p << 8 ) + *(p+1); \
    p += 2; \
    l -= 2

#define need32(v, p, l) \
    if (l < 4) { \
        return OMG_DNS_EINCOMP; \
    } \
    v = ( *p << 24 ) + ( *(p+1) << 16 ) + ( *(p+2) << 8 ) + *(p+3); \
    p += 4; \
    l -= 4

#define need64(v, p, l) \
    if (l < 8) { \
        return OMG_DNS_EINCOMP; \
    } \
    v = ( *p << 56 ) + ( *(p+1) << 48 ) + ( *(p+2) << 40 ) + ( *(p+3) << 32 ) + ( *(p+4) << 24 ) + ( *(p+5) << 16 ) + ( *(p+6) << 8 ) + *(p+7); \
    p += 8; \
    l -= 8

#define needxb(b, x, p, l) \
    if (l < x) { \
        return OMG_DNS_EINCOMP; \
    } \
    memcpy(b, p, x); \
    p += x; \
    l -= x

#define advancexb(x, p, l) \
    if (l < x) { \
        return OMG_DNS_EINCOMP; \
    } \
    p += x; \
    l -= x

/*
 * Label structure functions
 */

inline int omg_dns_label_is_end(const omg_dns_label_t* label) {
    omg_dns_assert(label);
    return label->is_end;
}

inline int omg_dns_label_have_length(const omg_dns_label_t* label) {
    omg_dns_assert(label);
    return label->have_length;
}

inline int omg_dns_label_have_offset(const omg_dns_label_t* label) {
    omg_dns_assert(label);
    return label->have_offset;
}

inline int omg_dns_label_have_extension_bits(const omg_dns_label_t* label) {
    omg_dns_assert(label);
    return label->have_extension_bits;
}

inline int omg_dns_label_have_dn(const omg_dns_label_t* label) {
    omg_dns_assert(label);
    return label->have_dn;
}

inline int omg_dns_label_is_complete(const omg_dns_label_t* label) {
    omg_dns_assert(label);
    return label->is_complete;
}

inline uint8_t omg_dns_label_length(const omg_dns_label_t* label) {
    omg_dns_assert(label);
    return label->length;
}

inline uint16_t omg_dns_label_offset(const omg_dns_label_t* label) {
    omg_dns_assert(label);
    return label->offset;
}

inline unsigned short omg_dns_label_extension_bits(const omg_dns_label_t* label) {
    omg_dns_assert(label);
    return label->extension_bits;
}

inline size_t omg_dns_label_dn_offset(const omg_dns_label_t* label) {
    omg_dns_assert(label);
    return label->dn_offset;
}


/*
 * Resource record structure callback functions
 */

inline omg_dns_label_callback_t omg_dns_rr_label_callback(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->label_callback;
}

inline void* omg_dns_rr_label_callback_context(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->label_callback_context;
}

inline void omg_dns_rr_set_label_callback(omg_dns_rr_t* rr, omg_dns_label_callback_t label_callback, void* label_callback_context) {
    omg_dns_assert(rr);
    rr->label_callback = label_callback;
    rr->label_callback_context = label_callback_context;
}

/*
 * Resource record structure functions
 */

inline int omg_dns_rr_is_question(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->is_question;
}

inline int omg_dns_rr_have_labels(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->have_labels;
}

inline int omg_dns_rr_have_type(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->have_type;
}

inline int omg_dns_rr_have_class(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->have_class;
}

inline int omg_dns_rr_have_ttl(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->have_ttl;
}

inline int omg_dns_rr_have_rdlength(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->have_rdlength;
}

inline int omg_dns_rr_have_rdata(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->have_rdata;
}

inline int omg_dns_rr_have_rdata_labels(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->have_rdata_labels;
}

inline int omg_dns_rr_have_padding(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->have_padding;
}

inline int omg_dns_rr_is_complete(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->is_complete;
}

inline size_t omg_dns_rr_bytes_parsed(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->bytes_parsed;
}

inline size_t omg_dns_rr_labels(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->labels;
}

inline uint16_t omg_dns_rr_type(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->type;
}

inline uint16_t omg_dns_rr_class(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->class;
}

inline uint32_t omg_dns_rr_ttl(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->ttl;
}

inline uint16_t omg_dns_rr_rdlength(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->rdlength;
}

inline size_t omg_dns_rr_rdata_offset(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->rdata_offset;
}

inline size_t omg_dns_rr_rdata_labels(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->rdata_labels;
}

inline size_t omg_dns_rr_padding_offset(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->padding_offset;
}

inline size_t omg_dns_rr_padding_length(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);
    return rr->padding_length;
}

inline size_t omg_dns_rr_num_rdata_labels(const omg_dns_rr_t* rr) {
    omg_dns_assert(rr);

    switch (rr->type) {
        case OMG_DNS_TYPE_NS:
        case OMG_DNS_TYPE_MD:
        case OMG_DNS_TYPE_MF:
        case OMG_DNS_TYPE_CNAME:
        case OMG_DNS_TYPE_MB:
        case OMG_DNS_TYPE_MG:
        case OMG_DNS_TYPE_MR:
        case OMG_DNS_TYPE_PTR:
        case OMG_DNS_TYPE_NXT:
        case OMG_DNS_TYPE_DNAME:
        case OMG_DNS_TYPE_NSEC:
        case OMG_DNS_TYPE_TKEY:
        case OMG_DNS_TYPE_TSIG:
            return 1;
            break;

        case OMG_DNS_TYPE_SOA:
        case OMG_DNS_TYPE_MINFO:
        case OMG_DNS_TYPE_RP:
        case OMG_DNS_TYPE_TALINK:
            return 2;
            break;

        case OMG_DNS_TYPE_MX:
        case OMG_DNS_TYPE_AFSDB:
        case OMG_DNS_TYPE_RT:
        case OMG_DNS_TYPE_KX:
        case OMG_DNS_TYPE_LP:
            return 1;
            break;

        case OMG_DNS_TYPE_PX:
            return 2;
            break;

        case OMG_DNS_TYPE_SIG:
        case OMG_DNS_TYPE_RRSIG:
            return 1;
            break;

        case OMG_DNS_TYPE_SRV:
            return 1;
            break;

        case OMG_DNS_TYPE_NAPTR:
            return 1;
            break;

        case OMG_DNS_TYPE_HIP: /* TODO */
            break;
    }

    return 0;
}

/*
 * DNS structure callback functions
 */

inline omg_dns_label_callback_t omg_dns_label_callback(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->label_callback;
}

inline void* omg_dns_label_callback_context(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->label_callback_context;
}

inline void omg_dns_set_label_callback(omg_dns_t* dns, omg_dns_label_callback_t label_callback, void* label_callback_context) {
    omg_dns_assert(dns);
    dns->label_callback = label_callback;
    dns->label_callback_context = label_callback_context;
}

inline omg_dns_rr_callback_t omg_dns_rr_callback(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->rr_callback;
}

inline void* omg_dns_rr_callback_context(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->rr_callback_context;
}

inline void omg_dns_set_rr_callback(omg_dns_t* dns, omg_dns_rr_callback_t rr_callback, void* rr_callback_context) {
    omg_dns_assert(dns);
    dns->rr_callback = rr_callback;
    dns->rr_callback_context = rr_callback_context;
}

/*
 * DNS structure functions
 */

inline int omg_dns_have_id(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_id;
}

inline int omg_dns_have_qr(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_qr;
}

inline int omg_dns_have_opcode(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_opcode;
}

inline int omg_dns_have_aa(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_aa;
}

inline int omg_dns_have_tc(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_tc;
}

inline int omg_dns_have_rd(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_rd;
}

inline int omg_dns_have_ra(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_ra;
}

inline int omg_dns_have_z(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_z;
}

inline int omg_dns_have_ad(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_ad;
}

inline int omg_dns_have_cd(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_cd;
}

inline int omg_dns_have_rcode(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_rcode;
}

inline int omg_dns_have_qdcount(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_qdcount;
}

inline int omg_dns_have_ancount(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_ancount;
}

inline int omg_dns_have_nscount(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_nscount;
}

inline int omg_dns_have_arcount(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_arcount;
}

inline int omg_dns_have_questions(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_questions;
}

inline int omg_dns_have_answers(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_answers;
}

inline int omg_dns_have_authorities(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_authorities;
}

inline int omg_dns_have_additionals(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_additionals;
}

inline int omg_dns_have_padding(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->have_padding;
}

inline int omg_dns_is_complete(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->is_complete;
}

inline size_t omg_dns_bytes_parsed(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->bytes_parsed;
}

inline uint16_t omg_dns_id(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->id;
}

inline int omg_dns_qr(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->qr;
}

inline int omg_dns_opcode(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->opcode;
}

inline int omg_dns_aa(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->aa;
}

inline int omg_dns_tc(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->tc;
}

inline int omg_dns_rd(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->rd;
}

inline int omg_dns_ra(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->ra;
}

inline int omg_dns_z(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->z;
}

inline int omg_dns_ad(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->ad;
}

inline int omg_dns_cd(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->cd;
}

inline int omg_dns_rcode(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->rcode;
}

inline uint16_t omg_dns_qdcount(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->qdcount;
}

inline uint16_t omg_dns_ancount(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->ancount;
}

inline uint16_t omg_dns_nscount(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->nscount;
}

inline uint16_t omg_dns_arcount(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->arcount;
}

inline size_t omg_dns_questions(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->questions;
}

inline size_t omg_dns_answers(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->answers;
}

inline size_t omg_dns_authorities(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->authorities;
}

inline size_t omg_dns_additionals(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->additionals;
}

inline size_t omg_dns_padding_offset(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->padding_offset;
}

inline size_t omg_dns_padding_length(const omg_dns_t* dns) {
    omg_dns_assert(dns);
    return dns->padding_length;
}

/*
 * Parsers
 */

 int omg_dns_parse_header(omg_dns_t* dns, const uint8_t* buffer, size_t length) {
     uint8_t byte;

     if (!dns) {
         return OMG_DNS_EINVAL;
     }

     need16(dns->id, buffer, length);
     dns->bytes_parsed += 2;
     dns->have_id = 1;

     need8(byte, buffer, length);
     dns->bytes_parsed += 1;
     dns->qr = byte & (1 << 7) ? 1 : 0;
     dns->opcode = ( byte >> 3 ) & 0xf;
     dns->aa = byte & (1 << 2) ? 1 : 0;
     dns->tc = byte & (1 << 1) ? 1 : 0;
     dns->rd = byte & (1 << 0) ? 1 : 0;
     dns->have_qr =
         dns->have_opcode =
         dns->have_aa =
         dns->have_tc =
         dns->have_rd = 1;

     need8(byte, buffer, length);
     dns->bytes_parsed += 1;
     dns->ra = byte & (1 << 7) ? 1 : 0;
     dns->z = byte & (1 << 6) ? 1 : 0;
     dns->ad = byte & (1 << 5) ? 1 : 0;
     dns->cd = byte & (1 << 4) ? 1 : 0;
     dns->rcode = byte & 0xf;
     dns->have_ra =
         dns->have_z =
         dns->have_ad =
         dns->have_cd =
         dns->have_rcode = 1;

     need16(dns->qdcount, buffer, length);
     dns->bytes_parsed += 2;
     dns->have_qdcount = 1;

     need16(dns->ancount, buffer, length);
     dns->bytes_parsed += 2;
     dns->have_ancount = 1;

     need16(dns->nscount, buffer, length);
     dns->bytes_parsed += 2;
     dns->have_nscount = 1;

     need16(dns->arcount, buffer, length);
     dns->bytes_parsed += 2;
     dns->have_arcount = 1;

     return OMG_DNS_OK;
}

int omg_dns_parse(omg_dns_t* dns, const uint8_t* buffer, size_t length) {
    size_t n;
    int ret;

    if (!dns) {
        return OMG_DNS_EINVAL;
    }

    if ((ret = omg_dns_parse_header(dns, buffer, length)) != OMG_DNS_OK) {
        return ret;
    }
    buffer += dns->bytes_parsed;
    length -= dns->bytes_parsed;

    for (n = dns->qdcount; n; n--) {
        omg_dns_rr_t rr = OMG_DNS_RR_T_INIT;

        rr._offset = dns->bytes_parsed;
        rr.is_question = 1;
        if (dns->label_callback)
            omg_dns_rr_set_label_callback(&rr, dns->label_callback, dns->label_callback_context);
        ret = omg_dns_parse_rr(&rr, buffer, length);
        if (dns->rr_callback)
            ret = dns->rr_callback(ret, &rr, dns->rr_callback_context);
        if (ret != OMG_DNS_OK)
            return ret;

        buffer += rr.bytes_parsed;
        length -= rr.bytes_parsed;
        dns->bytes_parsed += rr.bytes_parsed;

        dns->questions++;
    }
    dns->have_questions = 1;

    for (n = dns->ancount; n; n--) {
        omg_dns_rr_t rr = OMG_DNS_RR_T_INIT;

        rr._offset = dns->bytes_parsed;
        if (dns->label_callback)
            omg_dns_rr_set_label_callback(&rr, dns->label_callback, dns->label_callback_context);
        ret = omg_dns_parse_rr(&rr, buffer, length);
        if (dns->rr_callback)
            ret = dns->rr_callback(ret, &rr, dns->rr_callback_context);
        if (ret != OMG_DNS_OK)
            return ret;

        buffer += rr.bytes_parsed;
        length -= rr.bytes_parsed;
        dns->bytes_parsed += rr.bytes_parsed;

        dns->answers++;
    }
    dns->have_answers = 1;

    for (n = dns->nscount; n; n--) {
        omg_dns_rr_t rr = OMG_DNS_RR_T_INIT;

        rr._offset = dns->bytes_parsed;
        if (dns->label_callback)
            omg_dns_rr_set_label_callback(&rr, dns->label_callback, dns->label_callback_context);
        ret = omg_dns_parse_rr(&rr, buffer, length);
        if (dns->rr_callback)
            ret = dns->rr_callback(ret, &rr, dns->rr_callback_context);
        if (ret != OMG_DNS_OK)
            return ret;

        buffer += rr.bytes_parsed;
        length -= rr.bytes_parsed;
        dns->bytes_parsed += rr.bytes_parsed;

        dns->authorities++;
    }
    dns->have_authorities = 1;

    for (n = dns->arcount; n; n--) {
        omg_dns_rr_t rr = OMG_DNS_RR_T_INIT;

        rr._offset = dns->bytes_parsed;
        if (dns->label_callback)
            omg_dns_rr_set_label_callback(&rr, dns->label_callback, dns->label_callback_context);
        ret = omg_dns_parse_rr(&rr, buffer, length);
        if (dns->rr_callback)
            ret = dns->rr_callback(ret, &rr, dns->rr_callback_context);
        if (ret != OMG_DNS_OK)
            return ret;

        buffer += rr.bytes_parsed;
        length -= rr.bytes_parsed;
        dns->bytes_parsed += rr.bytes_parsed;

        dns->additionals++;
    }
    dns->have_additionals = 1;

    if (length) {
        dns->padding_offset = dns->bytes_parsed;
        dns->padding_length = length;
        dns->have_padding = 1;
    }

    dns->is_complete = 1;

    return OMG_DNS_OK;
}

int omg_dns_parse_rr(omg_dns_rr_t* rr, const uint8_t* buffer, size_t length) {
    int ret;
    size_t labels;

    if (!rr) {
        return OMG_DNS_EINVAL;
    }

    while (length) {
        omg_dns_label_t label = OMG_DNS_LABEL_T_INIT;

        label._offset = rr->_offset + rr->bytes_parsed;
        need8(label.length, buffer, length);
        rr->bytes_parsed += 1;

        if ((label.length & 0xc0) == 0xc0) {
            need8(label.offset, buffer, length);
            label.offset |= (label.length & 0x3f) << 8;
            rr->bytes_parsed += 1;
            label.have_offset = 1;

            label.is_complete = 1;
            if (rr->label_callback) {
                ret = rr->label_callback(&label, rr->label_callback_context);
                if (ret != OMG_DNS_OK)
                    return ret;
            }
            rr->labels++;
            break;
        }
        else if (label.length & 0xc0) {
            label.extension_bits = label.length >> 6;
            label.have_extension_bits = 1;

            label.is_complete = 1;
            if (rr->label_callback) {
                ret = rr->label_callback(&label, rr->label_callback_context);
                if (ret != OMG_DNS_OK)
                    return ret;
            }
            rr->labels++;
            break;
        }
        else if (label.length) {
            label.have_length = 1;

            label.offset = label._offset;
            label.dn_offset = label._offset + 1;
            advancexb(label.length, buffer, length);
            rr->bytes_parsed += label.length;
            label.have_dn = 1;

            label.is_complete = 1;
            if (rr->label_callback) {
                ret = rr->label_callback(&label, rr->label_callback_context);
                if (ret != OMG_DNS_OK)
                    return ret;
            }
            rr->labels++;
        }
        else {
            label.is_end = 1;
            label.is_complete = 1;
            if (rr->label_callback) {
                ret = rr->label_callback(&label, rr->label_callback_context);
                if (ret != OMG_DNS_OK)
                    return ret;
            }
            break;
        }
    }
    rr->have_labels = 1;

    need16(rr->type, buffer, length);
    rr->bytes_parsed += 2;
    rr->have_type = 1;

    need16(rr->class, buffer, length);
    rr->bytes_parsed += 2;
    rr->have_class = 1;

    if (rr->is_question) {
        rr->is_complete = 1;
        return OMG_DNS_OK;
    }

    need32(rr->ttl, buffer, length);
    rr->bytes_parsed += 4;
    rr->have_ttl = 1;

    need16(rr->rdlength, buffer, length);
    rr->bytes_parsed += 2;
    rr->have_rdlength = 1;

    rr->rdata_offset = rr->_offset + rr->bytes_parsed;

    if ((labels = omg_dns_rr_num_rdata_labels(rr))) {
        size_t bytes_parsed = 0;

        switch (rr->type) {
            case OMG_DNS_TYPE_MX:
            case OMG_DNS_TYPE_AFSDB:
            case OMG_DNS_TYPE_RT:
            case OMG_DNS_TYPE_KX:
            case OMG_DNS_TYPE_LP:
            case OMG_DNS_TYPE_PX:
                advancexb(2, buffer, length);
                rr->bytes_parsed += 2;
                bytes_parsed += 2;
                break;

            case OMG_DNS_TYPE_SIG:
            case OMG_DNS_TYPE_RRSIG:
                advancexb(18, buffer, length);
                rr->bytes_parsed += 18;
                bytes_parsed += 18;
                break;

            case OMG_DNS_TYPE_SRV:
                advancexb(6, buffer, length);
                rr->bytes_parsed += 6;
                bytes_parsed += 6;
                break;

            case OMG_DNS_TYPE_NAPTR:
                {
                    uint8_t naptr_length;

                    /* 2x 16 bits */
                    advancexb(4, buffer, length);
                    rr->bytes_parsed += 4;
                    bytes_parsed += 4;

                    need8(naptr_length, buffer, length);
                    rr->bytes_parsed += 1;
                    bytes_parsed += 1;
                    advancexb(naptr_length, buffer, length);
                    rr->bytes_parsed += naptr_length;
                    bytes_parsed += naptr_length;

                    need8(naptr_length, buffer, length);
                    rr->bytes_parsed += 1;
                    bytes_parsed += 1;
                    advancexb(naptr_length, buffer, length);
                    rr->bytes_parsed += naptr_length;
                    bytes_parsed += naptr_length;

                    need8(naptr_length, buffer, length);
                    rr->bytes_parsed += 1;
                    bytes_parsed += 1;
                    advancexb(naptr_length, buffer, length);
                    rr->bytes_parsed += naptr_length;
                    bytes_parsed += naptr_length;
                }
                break;

            case OMG_DNS_TYPE_HIP: /* TODO */
                break;
        }

        while (labels) {
            omg_dns_label_t label = OMG_DNS_LABEL_T_INIT;

            label._offset = rr->_offset + rr->bytes_parsed;
            need8(label.length, buffer, length);
            rr->bytes_parsed += 1;
            bytes_parsed += 1;

            if ((label.length & 0xc0) == 0xc0) {
                need8(label.offset, buffer, length);
                label.offset |= (label.length & 0x3f) << 8;
                rr->bytes_parsed += 1;
                bytes_parsed += 1;
                label.have_offset = 1;

                label.is_complete = 1;
                if (rr->label_callback) {
                    ret = rr->label_callback(&label, rr->label_callback_context);
                    if (ret != OMG_DNS_OK)
                        return ret;
                }
                rr->rdata_labels++;
                labels--;
                continue;
            }
            else if (label.length & 0xc0) {
                label.extension_bits = label.length >> 6;
                label.have_extension_bits = 1;

                label.is_complete = 1;
                if (rr->label_callback) {
                    ret = rr->label_callback(&label, rr->label_callback_context);
                    if (ret != OMG_DNS_OK)
                        return ret;
                }
                rr->rdata_labels++;
                labels--;
                continue;
            }
            else if (label.length) {
                label.have_length = 1;

                label.offset = label._offset;
                label.dn_offset = label._offset + 1;
                advancexb(label.length, buffer, length);
                rr->bytes_parsed += label.length;
                bytes_parsed += label.length;
                label.have_dn = 1;

                label.is_complete = 1;
                if (rr->label_callback) {
                    ret = rr->label_callback(&label, rr->label_callback_context);
                    if (ret != OMG_DNS_OK)
                        return ret;
                }
                rr->rdata_labels++;
            }
            else {
                label.is_end = 1;
                label.is_complete = 1;
                if (rr->label_callback) {
                    ret = rr->label_callback(&label, rr->label_callback_context);
                    if (ret != OMG_DNS_OK)
                        return ret;
                }
                labels--;
                continue;
            }
        }
        rr->have_rdata_labels = 1;

        if (bytes_parsed < rr->rdlength) {
            rr->padding_offset = rr->rdata_offset + bytes_parsed;
            rr->padding_length = rr->rdlength - bytes_parsed;

            advancexb(rr->padding_length, buffer, length);
            rr->bytes_parsed += rr->padding_length;

            /*
             * TODO:
             *
             * This can indicate padding but we do not set that we have padding
             * yet because we need to fully understand all record types before
             * that and process valid data after the labels
             *
            rr->have_padding = 1;
            */
        }
        else if (bytes_parsed > rr->rdlength) {
            return OMG_DNS_EOVERRUN;
        }

        rr->have_rdata = 1;
    }
    else {
        advancexb(rr->rdlength, buffer, length);
        rr->bytes_parsed += rr->rdlength;
        rr->have_rdata = 1;
    }

    rr->is_complete = 1;

    return OMG_DNS_OK;
}

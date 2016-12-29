/*
 * Author Jerry Lundström <jerry@dns-oarc.net>
 * Copyright (c) 2016, OARC, Inc.
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

#include "config.h"
#include "omg_dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define NUM_LABELS 512
struct labels {
    uint8_t*            data;
    size_t              label_idx;
    omg_dns_label_t*    label;
};

#define NUM_RRS 128
struct rrs {
    size_t          rr_idx;
    omg_dns_rr_t*   rr;
    int*            ret;
    size_t*         label_idx;
    struct labels*  labels;
};

static int print_labels = 0;

static int hex2byte(char hex) {
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    }
    else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    }
    else if (hex >= 'A' && hex <= 'F') {
        return hex - 'A' + 10;
    }

    return -1;
}

static void print_label(const omg_dns_label_t* label, const uint8_t* data, const char* prefix) {
    if (!label)
        return;

    printf("%slabel:\n", prefix ? prefix : "");
    if (omg_dns_label_is_end(label)) {
        printf("%s  end: yes\n", prefix ? prefix : "");
        return;
    }
    if (!omg_dns_label_is_complete(label)) {
        printf("%s  incomplete: yes\n", prefix ? prefix : "");
        return;
    }

    if (omg_dns_label_have_offset(label)) {
        printf("%s  offset: %d\n", prefix ? prefix : "", omg_dns_label_offset(label));
    }
    else if (omg_dns_label_have_extension_bits(label)) {
        printf("%s  extension_bits: %02x\n", prefix ? prefix : "", omg_dns_label_extension_bits(label));
    }
    else if (omg_dns_label_have_dn(label)) {
        if (data) {
            const uint8_t* dn = data + omg_dns_label_dn_offset(label);
            size_t dnlen = omg_dns_label_length(label);

            printf("%s  dn: ", prefix ? prefix : "");
            while (dnlen--) {
                printf("%c", *dn++);
            }
            printf("\n");
        }
        else {
            printf("%s  dn: NO_DATA\n", prefix ? prefix : "");
        }
    }
    else {
        printf("%s  invalid: yes\n", prefix ? prefix : "");
    }
}

int label_callback(const omg_dns_label_t* label, void* context) {
    struct labels* labels = (struct labels*)context;

    if (labels->label_idx == NUM_LABELS)
        return OMG_DNS_ENOMEM;

    labels->label[labels->label_idx] = *label;
    labels->label_idx++;

    return OMG_DNS_OK;
}

static int rr_callback(int ret, const omg_dns_rr_t* rr, void* context) {
    struct rrs* rrs = (struct rrs*)context;

    if (rrs->rr_idx == NUM_RRS)
        return OMG_DNS_ENOMEM;

    rrs->ret[rrs->rr_idx] = ret;
    if (rr)
        rrs->rr[rrs->rr_idx] = *rr;
    rrs->rr_idx++;
    if (rrs->rr_idx != NUM_RRS)
        rrs->label_idx[rrs->rr_idx] = rrs->labels->label_idx;

    return OMG_DNS_OK;
}

static void parse(uint8_t* data, size_t len) {
    omg_dns_t dns = OMG_DNS_T_INIT;
    int ret;
    struct rrs rrs = { 0, 0, 0 };
    struct labels labels = { 0, 0, 0 };
    size_t n;

    rrs.rr = calloc(NUM_RRS, sizeof(omg_dns_rr_t));
    rrs.ret = calloc(NUM_RRS, sizeof(int));
    rrs.label_idx = calloc(NUM_RRS, sizeof(size_t));
    rrs.labels = &labels;

    labels.data = data;
    labels.label = calloc(NUM_LABELS, sizeof(omg_dns_label_t));

    omg_dns_set_rr_callback(&dns, rr_callback, (void*)&rrs);
    omg_dns_set_label_callback(&dns, label_callback, (void*)&labels);
    ret = omg_dns_parse(&dns, data, len);

    if (omg_dns_have_id(&dns))
        printf("id: %u\n", omg_dns_id(&dns));
    if (omg_dns_have_qr(&dns))
        printf("  qr: %u\n", omg_dns_qr(&dns));
    if (omg_dns_have_opcode(&dns))
        printf("  opcode: %u\n", omg_dns_opcode(&dns));
    if (omg_dns_have_aa(&dns))
        printf("  aa: %u\n", omg_dns_aa(&dns));
    if (omg_dns_have_tc(&dns))
        printf("  tc: %u\n", omg_dns_tc(&dns));
    if (omg_dns_have_rd(&dns))
        printf("  rd: %u\n", omg_dns_rd(&dns));
    if (omg_dns_have_ra(&dns))
        printf("  ra: %u\n", omg_dns_ra(&dns));
    if (omg_dns_have_z(&dns))
        printf("  z: %u\n", omg_dns_z(&dns));
    if (omg_dns_have_ad(&dns))
        printf("  ad: %u\n", omg_dns_ad(&dns));
    if (omg_dns_have_cd(&dns))
        printf("  cd: %u\n", omg_dns_cd(&dns));
    if (omg_dns_have_rcode(&dns))
        printf("  rcode: %u\n", omg_dns_rcode(&dns));

    if (omg_dns_have_qdcount(&dns))
        printf("  qdcount: %u\n", omg_dns_qdcount(&dns));
    if (omg_dns_have_ancount(&dns))
        printf("  ancount: %u\n", omg_dns_ancount(&dns));
    if (omg_dns_have_nscount(&dns))
        printf("  nscount: %u\n", omg_dns_nscount(&dns));
    if (omg_dns_have_arcount(&dns))
        printf("  arcount: %u\n", omg_dns_arcount(&dns));

    if (omg_dns_have_questions(&dns))
        printf("  questions: %lu\n", omg_dns_questions(&dns));
    if (omg_dns_have_answers(&dns))
        printf("  answers: %lu\n", omg_dns_answers(&dns));
    if (omg_dns_have_authorities(&dns))
        printf("  authorities: %lu\n", omg_dns_authorities(&dns));
    if (omg_dns_have_additionals(&dns))
        printf("  additionals: %lu\n", omg_dns_additionals(&dns));

    if (print_labels) {
        printf("  labels:\n");
        for (n=0;n<labels.label_idx;n++) {
            print_label(&(labels.label[n]), data, "    ");
        }
    }

    for (n = 0; n < rrs.rr_idx; n++) {
        omg_dns_rr_t* rr = &(rrs.rr[n]);

        printf("  rr %lu\n", n);

        if (omg_dns_rr_have_labels(rr))
            printf("    labels: %lu\n", omg_dns_rr_labels(rr));

        if (omg_dns_rr_labels(rr)) {
            size_t l = rrs.label_idx[n];
            size_t loop = 0;

            printf("    label:");
            while (!omg_dns_label_is_end(&(labels.label[l]))) {
                if (!omg_dns_label_is_complete(&(labels.label[l]))) {
                    printf(" <incomplete>");
                    break;
                }

                if (loop > labels.label_idx) {
                    printf(" <loop detected>");
                    break;
                }
                loop++;

                if (omg_dns_label_have_offset(&(labels.label[l]))) {
                    size_t l2;

                    for (l2 = 0; l2 < labels.label_idx; l2++) {
                        if (omg_dns_label_have_dn(&(labels.label[l2]))
                            && omg_dns_label_offset(&(labels.label[l2])) == omg_dns_label_offset(&(labels.label[l])))
                        {
                            l = l2;
                            break;
                        }
                    }
                    if (l2 < labels.label_idx) {
                        printf(" <offset>");
                        continue;
                    }
                    printf(" <offset missing>");
                    break;
                }
                else if (omg_dns_label_have_extension_bits(&(labels.label[l]))) {
                    printf(" <extension>");
                    break;
                }
                else if (omg_dns_label_have_dn(&(labels.label[l]))) {
                    uint8_t* dn = data + omg_dns_label_dn_offset(&(labels.label[l]));
                    size_t dnlen = omg_dns_label_length(&(labels.label[l]));

                    printf(" ");
                    while (dnlen--) {
                        printf("%c", *dn++);
                    }
                    printf(" .");
                    l++;
                }
                else {
                    printf("<invalid>");
                    break;
                }
            }
            printf("\n");
        }

        printf("    question: %s\n", omg_dns_rr_is_question(rr) ? "yes" : "no");

        if (omg_dns_rr_have_type(rr))
            printf("    type: %u\n", omg_dns_rr_type(rr));
        if (omg_dns_rr_have_class(rr))
            printf("    class: %u\n", omg_dns_rr_class(rr));
        if (omg_dns_rr_have_ttl(rr))
            printf("    ttl: %u\n", omg_dns_rr_ttl(rr));
        if (omg_dns_rr_have_rdlength(rr))
            printf("    rdlength: %u\n", omg_dns_rr_rdlength(rr));
        if (omg_dns_rr_have_rdata(rr)) {
            uint8_t* rdata = data + omg_dns_rr_rdata_offset(rr);
            size_t rdatalen = omg_dns_rr_rdlength(rr);

            printf("    rdata: 0x");
            while (rdatalen--) {
                printf("%02x", *rdata++);
            }
            printf("\n");
        }

        if (omg_dns_rr_have_rdata_labels(rr))
            printf("    rdata labels: %lu\n", omg_dns_rr_rdata_labels(rr));

        if (omg_dns_rr_rdata_labels(rr)) {
            size_t rl = omg_dns_rr_num_rdata_labels(rr);
            size_t last = 0;

            while (rl--) {
                size_t l = rrs.label_idx[n] + omg_dns_rr_labels(rr) + last;
                size_t loop = 0;
                unsigned short jumped = 0;

                printf("    rdata label:");
                while (!omg_dns_label_is_end(&(labels.label[l]))) {
                    if (!jumped)
                        last++;

                    if (!omg_dns_label_is_complete(&(labels.label[l]))) {
                        printf(" <incomplete>");
                        break;
                    }

                    if (loop > labels.label_idx) {
                        printf(" <loop detected>");
                        break;
                    }
                    loop++;

                    if (omg_dns_label_have_offset(&(labels.label[l]))) {
                        size_t l2;

                        for (l2 = 0; l2 < labels.label_idx; l2++) {
                            if (omg_dns_label_have_dn(&(labels.label[l2]))
                                && omg_dns_label_offset(&(labels.label[l2])) == omg_dns_label_offset(&(labels.label[l])))
                            {
                                l = l2;
                                break;
                            }
                        }
                        if (l2 < labels.label_idx) {
                            jumped = 1;
                            printf(" <offset>");
                            continue;
                        }
                        printf(" <offset missing>");
                        break;
                    }
                    else if (omg_dns_label_have_extension_bits(&(labels.label[l]))) {
                        printf(" <extension>");
                        break;
                    }
                    else if (omg_dns_label_have_dn(&(labels.label[l]))) {
                        uint8_t* dn = data + omg_dns_label_dn_offset(&(labels.label[l]));
                        size_t dnlen = omg_dns_label_length(&(labels.label[l]));

                        printf(" ");
                        while (dnlen--) {
                            printf("%c", *dn++);
                        }
                        printf(" .");
                        l++;
                    }
                    else {
                        printf("<invalid>");
                        break;
                    }
                }
                printf("\n");
            }
        }

        if (omg_dns_rr_have_padding(rr)) {
            uint8_t* pad = data + omg_dns_rr_padding_offset(rr);
            size_t padlen = omg_dns_rr_padding_length(rr);

            printf("    padding: 0x");
            while (padlen--) {
                printf("%02x", *pad++);
            }
            printf("\n");
        }

        printf("    complete: %s\n", omg_dns_rr_is_complete(rr) ? "yes" : "no");
        printf("    ret: %d\n", rrs.ret[n]);
    }

    if (omg_dns_have_padding(&dns)) {
        uint8_t* pad = data + omg_dns_padding_offset(&dns);
        size_t padlen = omg_dns_padding_length(&dns);

        printf("  padding: 0x");
        while (padlen--) {
            printf("%02x", *pad++);
        }
        printf("\n");
    }

    printf("  complete: %s\n", omg_dns_is_complete(&dns) ? "yes" : "no");
    printf("  ret: %d\n", ret);

    free(rrs.rr);
    free(rrs.ret);
    free(rrs.label_idx);
    free(labels.label);
}

int main(int argc, char** argv) {
    int opt, err = 0;
    uint8_t dns[64*1024];

    while ((opt = getopt(argc, argv, "lhV")) != -1) {
        switch (opt) {
            case 'l':
                print_labels = 1;
                break;

            case 'h':
                printf(
"usage: hexdns2text [options] <dns packets in hex...>\n"
" -l                 also print a list of all labels\n"
" -V                 display version and exit\n"
" -h                 this\n"
                );
                exit(0);

            case 'V':
                printf("hexdns2text version %s (omg_dns version %s)\n",
                    PACKAGE_VERSION,
                    OMG_DNS_VERSION_STR
                );
                exit(0);

            default:
                err = -1;
        }
    }

    if (err == -2) {
        fprintf(stderr, "Unsupported argument(s)\n");
        exit(1);
    }
    if (err == -1) {
        fprintf(stderr, "Invalid argument(s)\n");
        exit(1);
    }

    while (optind < argc) {
        size_t len = strlen(argv[optind]), n;
        char* hex = argv[optind];
        uint8_t* byte = dns;
        int high, low;

        if (len % 2) {
            fprintf(stderr, "Invalid HEX, odd number of characters\n");
            exit(2);
        }
        if ((len / 2) > sizeof(dns)) {
            fprintf(stderr, "Invalid HEX, too large\n");
            exit(2);
        }

        memset(dns, 0, sizeof(dns));
        n = len;
        while (n) {
            if ((high = hex2byte(*hex)) < 0) {
                fprintf(stderr, "Invalid HEX, %c not a valid HEX character\n", *hex);
                exit(2);
            }
            hex++;
            if ((low = hex2byte(*hex)) < 0) {
                fprintf(stderr, "Invalid HEX, %c not a valid HEX character\n", *hex);
                exit(2);
            }
            hex++;

            *byte = (high << 4) | low;
            byte++;
            n -= 2;
        }

        parse(dns, len / 2);

        optind++;
    }


    return 0;
}

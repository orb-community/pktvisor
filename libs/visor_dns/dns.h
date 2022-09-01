/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "DnsLayer.h"
#include "DnsResource.h"
#include "DnsResourceData.h"
#include <string>
#include <unordered_map>

namespace visor::dns {

typedef std::pair<std::string_view, std::string_view> AggDomainResult;
AggDomainResult aggregateDomain(const std::string &domain, size_t suffix_size = 0);

enum QR {
    query = 0,
    response = 1
};

enum RCode {
    NoError = 0,
    SrvFail = 2,
    NXDomain = 3,
    Refused = 5
};

static std::unordered_map<uint16_t, std::string> QTypeNames({
    {1, "A"},
    {2, "NS"},
    {3, "MD"},
    {4, "MF"},
    {5, "CNAME"},
    {6, "SOA"},
    {7, "MB"},
    {8, "MG"},
    {9, "MR"},
    {10, "NULL"},
    {11, "WKS"},
    {12, "PTR"},
    {13, "HINFO"},
    {14, "MINFO"},
    {15, "MX"},
    {16, "TXT"},
    {17, "RP"},
    {18, "AFSDB"},
    {19, "X25"},
    {20, "ISDN"},
    {21, "RT"},
    {22, "NSAP"},
    {23, "NSAP-PTR"},
    {24, "SIG"},
    {25, "KEY"},
    {26, "PX"},
    {27, "GPOS"},
    {28, "AAAA"},
    {29, "LOC"},
    {30, "NXT"},
    {31, "EID"},
    {32, "NIMLOC"},
    {33, "SRV"},
    {35, "NAPTR"},
    {36, "KX"},
    {37, "CERT"},
    {38, "A6"},
    {39, "DNAME"},
    {40, "SINK"},
    {41, "OPT"},
    {42, "APL"},
    {43, "DS"},
    {44, "SSHFP"},
    {45, "IPSECKEY"},
    {46, "RRSIG"},
    {47, "NSEC"},
    {48, "DNSKEY"},
    {49, "DHCID"},
    {50, "NSEC3"},
    {51, "NSEC3PARAM"},
    {52, "TLSA"},
    {53, "SMIMEA"},
    {55, "HIP"},
    {56, "NINFO"},
    {57, "RKEY"},
    {58, "TALINK"},
    {59, "CDS"},
    {60, "CDNSKEY"},
    {61, "OPENPGPKEY"},
    {62, "CSYNC"},
    {63, "ZONEMD"},
    {64, "SVCB"},
    {65, "HTTPS"},
    {99, "SPF"},
    {100, "UINFO"},
    {101, "UID"},
    {102, "GID"},
    {103, "UNSPEC"},
    {104, "NID"},
    {105, "L32"},
    {106, "L64"},
    {107, "LP"},
    {108, "EUI48"},
    {109, "EUI64"},
    {249, "TKEY"},
    {250, "TSIG"},
    {251, "IXFR"},
    {252, "AXFR"},
    {253, "MAILB"},
    {254, "MAILA"},
    {256, "URI"},
    {257, "CAA"},
    {258, "AVC"},
    {259, "DOA"},
    {260, "AMTRELAY"},
});

static std::unordered_map<std::string, uint16_t> QTypeNumbers({
    {"A", 1},
    {"NS", 2},
    {"MD", 3},
    {"MF", 4},
    {"CNAME", 5},
    {"SOA", 6},
    {"MB", 7},
    {"MG", 8},
    {"MR", 9},
    {"NULL", 10},
    {"WKS", 11},
    {"PTR", 12},
    {"HINFO", 13},
    {"MINFO", 14},
    {"MX", 15},
    {"TXT", 16},
    {"RP", 17},
    {"AFSDB", 18},
    {"X25", 19},
    {"ISDN", 20},
    {"RT", 21},
    {"NSAP", 22},
    {"NSAP-PTR", 23},
    {"SIG", 24},
    {"KEY", 25},
    {"PX", 26},
    {"GPOS", 27},
    {"AAAA", 28},
    {"LOC", 29},
    {"NXT", 30},
    {"EID", 31},
    {"NIMLOC", 32},
    {"SRV", 33},
    {"NAPTR", 35},
    {"KX", 36},
    {"CERT", 37},
    {"A6", 38},
    {"DNAME", 39},
    {"SINK", 40},
    {"OPT", 41},
    {"APL", 42},
    {"DS", 43},
    {"SSHFP", 44},
    {"IPSECKEY", 45},
    {"RRSIG", 46},
    {"NSEC", 47},
    {"DNSKEY", 48},
    {"DHCID", 49},
    {"NSEC3", 50},
    {"NSEC3PARAM", 51},
    {"TLSA", 52},
    {"SMIMEA", 53},
    {"HIP", 55},
    {"NINFO", 56},
    {"RKEY", 57},
    {"TALINK", 58},
    {"CDS", 59},
    {"CDNSKEY", 60},
    {"OPENPGPKEY", 61},
    {"CSYNC", 62},
    {"ZONEMD", 63},
    {"SVCB", 64},
    {"HTTPS", 65},
    {"SPF", 99},
    {"UINFO", 100},
    {"UID", 101},
    {"GID", 102},
    {"UNSPEC", 103},
    {"NID", 104},
    {"L32", 105},
    {"L64", 106},
    {"LP", 107},
    {"EUI48", 108},
    {"EUI64", 109},
    {"TKEY", 249},
    {"TSIG", 250},
    {"IXFR", 251},
    {"AXFR", 252},
    {"MAILB", 253},
    {"MAILA", 554},
    {"URI", 256},
    {"CAA", 257},
    {"AVC", 258},
    {"DOA", 259},
    {"AMTRELAY", 260},
});

static std::unordered_map<uint16_t, std::string> RCodeNames({
    {0, "NOERROR"},
    {1, "FORMERR"},
    {2, "SRVFAIL"},
    {3, "NXDOMAIN"},
    {4, "NOTIMP"},
    {5, "REFUSED"},
    {6, "YXDOMAIN"},
    {7, "YXRRSET"},
    {8, "NXRRSET"},
    {9, "NOTAUTH"},
    {9, "NOTAUTH"},
    {10, "NOTZONE"},
    {11, "DSOTYPENI"},
    {16, "BADVERS"},
    {16, "BADSIG"},
    {17, "BADKEY"},
    {18, "BADTIME"},
    {19, "BADMODE"},
    {20, "BADNAME"},
    {21, "BADALG"},
    {22, "BADTRUNC"},
    {23, "BADCOOKIE"},
});

}
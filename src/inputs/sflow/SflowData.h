#pragma once

#include <sflow.h>
#include <sflow_v2v4.h>
#include <netinet/in.h>

#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
#define NFT_ETHHDR_SIZ 14
#define NFT_MAX_8023_LEN 1500
#define WIFI_MIN_HDR_SIZ 24

namespace visor::input::sflow {

enum ExtendedData {
    SWITCH = 1,
    ROUTER = 4,
    GATEWAY = 8,
    USER = 16,
    URL = 32,
    MPLS = 64,
    NAT = 128,
    MPLS_TUNNEL = 256,
    MPLS_VC = 512,
    MPLS_FTN = 1024,
    MPLS_LDP_FEC = 2048,
    VLAN_TUNNEL = 4096,
    NAT_PORT = 8192
};

/* define my own IP header struct - to ease portability */
struct myiphdr {
    uint8_t version_and_headerLen;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

/* ip6 header if no option headers */
struct myip6hdr {
    uint8_t version_and_priority;
    uint8_t priority_and_label1;
    uint8_t label2;
    uint8_t label3;
    uint16_t payloadLength;
    uint8_t nextHeader;
    uint8_t ttl;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

/* same for tcp */
struct mytcphdr {
    uint16_t th_sport; /* source port */
    uint16_t th_dport; /* destination port */
    uint32_t th_seq;   /* sequence number */
    uint32_t th_ack;   /* acknowledgement number */
    uint8_t th_off_and_unused;
    uint8_t th_flags;
    uint16_t th_win; /* window */
    uint16_t th_sum; /* checksum */
    uint16_t th_urp; /* urgent pointer */
};

/* and UDP */
struct myudphdr {
    uint16_t uh_sport; /* source port */
    uint16_t uh_dport; /* destination port */
    uint16_t uh_ulen;  /* udp length */
    uint16_t uh_sum;   /* udp checksum */
};

/* and ICMP */
struct myicmphdr {
    uint8_t type; /* message type */
    uint8_t code; /* type sub-code */
                  /* ignore the rest */
};

struct SFSample {
    /* the raw pdu */
    uint8_t *rawSample;
    uint32_t rawSampleLen;
    uint8_t *endp;
    time_t pcapTimestamp;
    time_t readTimestamp;

    /* decode cursor */
    uint32_t *datap;

    /* datagram fields */
    SFLAddress sourceIP;
    SFLAddress agent_addr;
    uint32_t agentSubId;
    uint32_t datagramVersion;
    uint32_t sysUpTime;
    uint32_t sequenceNo;

    /* per-element fields */
    struct {
        uint32_t prefixCount;
        char *fieldPrefix[4];

        uint32_t sampleType;
        uint32_t elementType;
        uint32_t ds_class;
        uint32_t ds_index;

        /* generic interface counter sample */
        SFLIf_counters ifCounters;

        /* data-source stream info */
        uint32_t samplesGenerated;
        uint32_t meanSkipCount;
        uint32_t samplePool;
        uint32_t dropEvents;

        /* the sampled header */
        uint32_t sampledPacketSize;
        uint32_t packet_data_tag;
        uint32_t headerProtocol;
        uint8_t *header;
        uint32_t headerLen;
        uint32_t stripped;

        /* header decode */
        int gotIPV4;
        int gotIPV4Struct;
        int offsetToIPV4;
        int gotIPV6;
        int gotIPV6Struct;
        int offsetToIPV6;
        int offsetToPayload;
        SFLAddress ipsrc;
        SFLAddress ipdst;
        uint32_t dcd_ipProtocol;
        uint32_t dcd_ipTos;
        uint32_t dcd_ipTTL;
        uint32_t dcd_sport;
        uint32_t dcd_dport;
        uint32_t dcd_tcpFlags;
        uint32_t ip_fragmentOffset;
        uint32_t udp_pduLen;

        /* ports */
        uint32_t inputPortFormat;
        uint32_t outputPortFormat;
        uint32_t inputPort;
        uint32_t outputPort;

        /* ethernet */
        uint32_t eth_type;
        uint32_t eth_len;
        uint8_t eth_src[8];
        uint8_t eth_dst[8];

        /* vlan */
        uint32_t in_vlan;
        uint32_t in_priority;
        uint32_t internalPriority;
        uint32_t out_vlan;
        uint32_t out_priority;
        int vlanFilterReject;

        /* extended data fields */
        uint32_t num_extended;
        uint32_t extended_data_tag;

        /* IP forwarding info */
        SFLAddress nextHop;
        uint32_t srcMask;
        uint32_t dstMask;

        /* BGP info */
        SFLAddress bgp_nextHop;
        uint32_t my_as;
        uint32_t src_as;
        uint32_t src_peer_as;
        uint32_t dst_as_path_len;
        uint32_t *dst_as_path;
        /* note: version 4 dst as path segments just get printed, not stored here, however
         * the dst_peer and dst_as are filled in, since those are used for netflow encoding
         */
        uint32_t dst_peer_as;
        uint32_t dst_as;

        uint32_t communities_len;
        uint32_t *communities;
        uint32_t localpref;

        /* mpls */
        SFLAddress mpls_nextHop;

        /* nat */
        SFLAddress nat_src;
        SFLAddress nat_dst;

        /* counter blocks */
        uint32_t statsSamplingInterval;
        uint32_t counterBlockVersion;
    } s;
};

inline static uint32_t getData32_nobswap(SFSample *sample)
{
    uint32_t ans = *(sample->datap)++;
    if ((uint8_t *)sample->datap > sample->endp) {
        throw std::out_of_range("reading out of datagram range");
    }
    return ans;
}

inline static uint32_t getData32(SFSample *sample)
{
    return ntohl(getData32_nobswap(sample));
}

inline static void skipBytes(SFSample *sample, uint32_t skip)
{
    int quads = (skip + 3) / 4;
    sample->datap += quads;
    if (skip > sample->rawSampleLen || (uint8_t *)sample->datap > sample->endp) {
        throw std::out_of_range("skipping bytes out of datagram range");
    }
}

static uint32_t getAddress(SFSample *sample, SFLAddress *address)
{
    address->type = getData32(sample);
    if (address->type == SFLADDRESSTYPE_IP_V4) {
        address->address.ip_v4.addr = getData32_nobswap(sample);
    } else {
        /* make sure the data is there before we memcpy */
        uint32_t *dp = sample->datap;
        skipBytes(sample, 16);
        std::memcpy(&address->address.ip_v6.addr, dp, 16);
    }

    return address->type;
}

static void lengthCheck(SFSample *sample, char *description, uint8_t *start, int len)
{
    uint32_t actualLen = (uint8_t *)sample->datap - start;
    uint32_t adjustedLen = ((len + 3) >> 2) << 2;
    if (actualLen != adjustedLen) {
        throw std::length_error(fmt::format("{} length error (expected {}, found {})", description, len, actualLen));
    }
}

static void decodeLinkLayer(SFSample *sample)
{
    uint8_t *start = sample->s.header;
    uint8_t *end = start + sample->s.headerLen;
    uint8_t *ptr = start;
    uint16_t type_len;
    uint32_t vlanDepth = 0;

    /* assume not found */
    sample->s.gotIPV4 = 0;
    sample->s.gotIPV6 = 0;

    if ((end - ptr) < NFT_ETHHDR_SIZ) {
        return; /* not enough for an Ethernet header */
    }

    std::memcpy(sample->s.eth_dst, ptr, 6);
    ptr += 6;
    std::memcpy(sample->s.eth_src, ptr, 6);
    ptr += 6;
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;

    while (type_len == 0x8100
        || type_len == 0x88A8
        || type_len == 0x9100
        || type_len == 0x9200
        || type_len == 0x9300) {
        if ((end - ptr) < 4)
            return; /* not enough for an 802.1Q header */
        /* VLAN  - next two bytes */
        uint32_t vlanData = (ptr[0] << 8) + ptr[1];
        uint32_t vlan = vlanData & 0x0fff;
        uint32_t priority = vlanData >> 13;
        ptr += 2;
        /*  _____________________________________ */
        /* |   pri  | c |         vlan-id        | */
        /*  ------------------------------------- */
        /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
        sample->s.in_vlan = vlan;
        /* now get the type_len again (next two bytes) */
        type_len = (ptr[0] << 8) + ptr[1];
        ptr += 2;
        vlanDepth++;
    }

    /* now we're just looking for IP */
    if ((end - start) < sizeof(struct myiphdr))
        return; /* not enough for an IPv4 header (or IPX, or SNAP) */

    /* peek for IPX */
    if (type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
        int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
        int ipxLen = (ptr[2] << 8) + ptr[3];
        if (ipxChecksum && ipxLen >= IPX_HDR_LEN && ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
            /* we don't do anything with IPX here */
            return;
    }
    if (type_len <= NFT_MAX_8023_LEN) {
        /* assume 802.3+802.2 header */
        /* check for SNAP */
        if (ptr[0] == 0xAA && ptr[1] == 0xAA && ptr[2] == 0x03) {
            ptr += 3;
            if (ptr[0] != 0 || ptr[1] != 0 || ptr[2] != 0) {
                return; /* no further decode for vendor-specific protocol */
            }
            ptr += 3;
            /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
            type_len = (ptr[0] << 8) + ptr[1];
            ptr += 2;
        } else {
            if (ptr[0] == 0x06 && ptr[1] == 0x06 && (ptr[2] & 0x01)) {
                /* IP over 8022 */
                ptr += 3;
                /* force the type_len to be IP so we can inline the IP decode below */
                type_len = 0x0800;
            } else
                return;
        }
    }

    /* assume type_len is an ethernet-type now */
    sample->s.eth_type = type_len;

    if (type_len == 0x0800) {
        /* IPV4 - check again that we have enough header bytes */
        if ((end - ptr) < sizeof(struct myiphdr))
            return;
        /* look at first byte of header.... */
        /*  ___________________________ */
        /* |   version   |    hdrlen   | */
        /*  --------------------------- */
        if ((*ptr >> 4) != 4)
            return; /* not version 4 */
        if ((*ptr & 15) < 5)
            return; /* not IP (hdr len must be 5 quads or more) */
        /* survived all the tests - store the offset to the start of the ip header */
        sample->s.gotIPV4 = 1;
        sample->s.offsetToIPV4 = (ptr - start);
    }

    if (type_len == 0x86DD) {
        /* IPV6 */
        /* look at first byte of header.... */
        if ((*ptr >> 4) != 6)
            return; /* not version 6 */
        /* survived all the tests - store the offset to the start of the ip6 header */
        sample->s.gotIPV6 = 1;
        sample->s.offsetToIPV6 = (ptr - start);
    }
}

static void decode80211MAC(SFSample *sample)
{
    uint8_t *start = sample->s.header;
    uint8_t *end = start + sample->s.headerLen;
    uint8_t *ptr = start;

    /* assume not found */
    sample->s.gotIPV4 = 0;
    sample->s.gotIPV6 = 0;

    if (sample->s.headerLen < WIFI_MIN_HDR_SIZ) {
        return; /* not enough for an 80211 MAC header */
    }

    uint32_t fc = (ptr[1] << 8) + ptr[0]; /* [b7..b0][b15..b8] */
    uint32_t protocolVersion = fc & 3;
    uint32_t control = (fc >> 2) & 3;
    uint32_t subType = (fc >> 4) & 15;
    uint32_t toDS = (fc >> 8) & 1;
    uint32_t fromDS = (fc >> 9) & 1;
    uint32_t moreFrag = (fc >> 10) & 1;
    uint32_t retry = (fc >> 11) & 1;
    uint32_t pwrMgt = (fc >> 12) & 1;
    uint32_t moreData = (fc >> 13) & 1;
    uint32_t encrypted = (fc >> 14) & 1;
    uint32_t order = fc >> 15;

    ptr += 2;

    uint32_t duration_id = (ptr[1] << 8) + ptr[0]; /* not in network byte order either? */
    ptr += 2;

    switch (control) {
    case 0: /* mgmt */
    case 1: /* ctrl */
    case 3: /* rsvd */
        break;

    case 2: /* data */
    {

        uint8_t *macAddr1 = ptr;
        ptr += 6;
        uint8_t *macAddr2 = ptr;
        ptr += 6;
        uint8_t *macAddr3 = ptr;
        ptr += 6;
        uint32_t sequence = (ptr[0] << 8) + ptr[1];
        ptr += 2;

        /* ToDS   FromDS   Addr1   Addr2  Addr3   Addr4
           0      0        DA      SA     BSSID   N/A (ad-hoc)
           0      1        DA      BSSID  SA      N/A
           1      0        BSSID   SA     DA      N/A
           1      1        RA      TA     DA      SA  (wireless bridge) */

        uint8_t *srcMAC = NULL;
        uint8_t *dstMAC = NULL;

        if (toDS) {
            dstMAC = macAddr3;
            if (fromDS) {
                srcMAC = ptr; /* macAddr4.  1,1 => (wireless bridge) */
                ptr += 6;
            } else
                srcMAC = macAddr2; /* 1,0 */
        } else {
            dstMAC = macAddr1;
            if (fromDS)
                srcMAC = macAddr3; /* 0,1 */
            else
                srcMAC = macAddr2; /* 0,0 */
        }

        if (srcMAC) {
            std::memcpy(sample->s.eth_src, srcMAC, 6);
        }
        if (dstMAC) {
            std::memcpy(sample->s.eth_dst, srcMAC, 6);
        }
    }
    }
}

static void decodeIPLayer4(SFSample *sample, uint8_t *ptr)
{
    uint8_t *end = sample->s.header + sample->s.headerLen;
    if (ptr > (end - 8)) {
        /* not enough header bytes left */
        return;
    }
    switch (sample->s.dcd_ipProtocol) {
    case 1: /* ICMP */
    {
        struct myicmphdr icmp;
        memcpy(&icmp, ptr, sizeof(icmp));
        sample->s.dcd_sport = icmp.type;
        sample->s.dcd_dport = icmp.code;
        sample->s.offsetToPayload = ptr + sizeof(icmp) - sample->s.header;
    } break;
    case 6: /* TCP */
    {
        struct mytcphdr tcp;
        int headerBytes;
        memcpy(&tcp, ptr, sizeof(tcp));
        sample->s.dcd_sport = ntohs(tcp.th_sport);
        sample->s.dcd_dport = ntohs(tcp.th_dport);
        sample->s.dcd_tcpFlags = tcp.th_flags;
        headerBytes = (tcp.th_off_and_unused >> 4) * 4;
        ptr += headerBytes;
        sample->s.offsetToPayload = ptr - sample->s.header;
    } break;
    case 17: /* UDP */
    {
        struct myudphdr udp;
        memcpy(&udp, ptr, sizeof(udp));
        sample->s.dcd_sport = ntohs(udp.uh_sport);
        sample->s.dcd_dport = ntohs(udp.uh_dport);
        sample->s.udp_pduLen = ntohs(udp.uh_ulen);
        sample->s.offsetToPayload = ptr + sizeof(udp) - sample->s.header;
    } break;
    default: /* some other protcol */
        sample->s.offsetToPayload = ptr - sample->s.header;
        break;
    }
}

static void decodeIPV4(SFSample *sample)
{
    if (sample->s.gotIPV4) {
        uint8_t *end = sample->s.header + sample->s.headerLen;
        uint8_t *start = sample->s.header + sample->s.offsetToIPV4;
        uint8_t *ptr = start;
        if ((end - ptr) < sizeof(struct myiphdr))
            return;

        /* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
           platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
        struct myiphdr ip;
        memcpy(&ip, ptr, sizeof(ip));
        /* Value copy all ip elements into sample */
        sample->s.ipsrc.type = SFLADDRESSTYPE_IP_V4;
        sample->s.ipsrc.address.ip_v4.addr = ip.saddr;
        sample->s.ipdst.type = SFLADDRESSTYPE_IP_V4;
        sample->s.ipdst.address.ip_v4.addr = ip.daddr;
        sample->s.dcd_ipProtocol = ip.protocol;
        sample->s.dcd_ipTos = ip.tos;
        sample->s.dcd_ipTTL = ip.ttl;
        /* check for fragments */
        sample->s.ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
        if (sample->s.ip_fragmentOffset > 0) {
            return;
        } else {
            /* advance the pointer to the next protocol layer */
            /* ip headerLen is expressed as a number of quads */
            uint32_t headerBytes = (ip.version_and_headerLen & 0x0f) * 4;
            if ((end - ptr) < headerBytes) {
                return;
            }
            ptr += headerBytes;
            decodeIPLayer4(sample, ptr);
        }
    }
}

static void decodeIPV6(SFSample *sample)
{
    uint16_t payloadLen;
    uint32_t label;
    uint32_t nextHeader;
    uint32_t tos;

    uint8_t *end = sample->s.header + sample->s.headerLen;
    uint8_t *start = sample->s.header + sample->s.offsetToIPV6;
    uint8_t *ptr = start;
    if ((end - ptr) < sizeof(struct myip6hdr))
        return;

    if (sample->s.gotIPV6) {

        /* check the version */
        {
            int ipVersion = (*ptr >> 4);
            if (ipVersion != 6) {
                return;
            }
        }

        /* get the tos (priority) */
        sample->s.dcd_ipTos = ((ptr[0] & 15) << 4) + (ptr[1] >> 4);
        ptr++;
        /* 20-bit label */
        label = ((ptr[0] & 15) << 16) + (ptr[1] << 8) + ptr[2];
        ptr += 3;
        /* payload */
        payloadLen = (ptr[0] << 8) + ptr[1];
        ptr += 2;

        /* next header */
        nextHeader = *ptr++;

        /* TTL */
        sample->s.dcd_ipTTL = *ptr++;

        { /* src and dst address */
            sample->s.ipsrc.type = SFLADDRESSTYPE_IP_V6;
            std::memcpy(&sample->s.ipsrc.address, ptr, 16);
            ptr += 16;
            sample->s.ipdst.type = SFLADDRESSTYPE_IP_V6;
            std::memcpy(&sample->s.ipdst.address, ptr, 16);
            ptr += 16;
        }

        /* skip over some common header extensions...
           http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html */
        while (nextHeader == 0 || /* hop */
            nextHeader == 43 ||   /* routing */
            nextHeader == 44 ||   /* fragment */
            /* nextHeader == 50 => encryption - don't bother coz we'll not be able to read any further */
            nextHeader == 51 || /* auth */
            nextHeader == 60) { /* destination options */
            uint32_t optionLen;
            nextHeader = ptr[0];
            optionLen = 8 * (ptr[1] + 1); /* second byte gives option len in 8-byte chunks, not counting first 8 */
            ptr += optionLen;
            if (ptr > end) {
                return; /* ran off the end of the header */
            }
        }

        /* now that we have eliminated the extension headers, nextHeader should have what we want to
           remember as the ip protocol... */
        sample->s.dcd_ipProtocol = nextHeader;
        decodeIPLayer4(sample, ptr);
    }
}

static void readFlowSample_IPv4(SFSample *sample)
{
    sample->s.headerLen = sizeof(SFLSampled_ipv4);
    sample->s.header = (uint8_t *)sample->datap; /* just point at the header */
    skipBytes(sample, sample->s.headerLen);

    SFLSampled_ipv4 nfKey;
    std::memcpy(&nfKey, sample->s.header, sizeof(nfKey));
    sample->s.sampledPacketSize = ntohl(nfKey.length);

    sample->s.ipsrc.type = SFLADDRESSTYPE_IP_V4;
    sample->s.ipsrc.address.ip_v4 = nfKey.src_ip;
    sample->s.ipdst.type = SFLADDRESSTYPE_IP_V4;
    sample->s.ipdst.address.ip_v4 = nfKey.dst_ip;
    sample->s.dcd_ipProtocol = ntohl(nfKey.protocol);
    sample->s.dcd_ipTos = ntohl(nfKey.tos);

    sample->s.dcd_sport = ntohl(nfKey.src_port);
    sample->s.dcd_dport = ntohl(nfKey.dst_port);

    /* TCP */
    if (sample->s.dcd_ipProtocol == 6) {
        sample->s.dcd_tcpFlags = ntohl(nfKey.tcp_flags);
    }
}

static void readFlowSample_IPv6(SFSample *sample)
{
    sample->s.header = (uint8_t *)sample->datap; /* just point at the header */
    sample->s.headerLen = sizeof(SFLSampled_ipv6);
    skipBytes(sample, sample->s.headerLen);

    SFLSampled_ipv6 nfKey6;
    std::memcpy(&nfKey6, sample->s.header, sizeof(nfKey6));
    sample->s.sampledPacketSize = ntohl(nfKey6.length);

    sample->s.ipsrc.type = SFLADDRESSTYPE_IP_V6;
    std::memcpy(&sample->s.ipsrc.address.ip_v6, &nfKey6.src_ip, 16);
    sample->s.ipdst.type = SFLADDRESSTYPE_IP_V6;
    std::memcpy(&sample->s.ipdst.address.ip_v6, &nfKey6.dst_ip, 16);
    sample->s.dcd_ipProtocol = ntohl(nfKey6.protocol);
    sample->s.dcd_sport = ntohl(nfKey6.src_port);
    sample->s.dcd_dport = ntohl(nfKey6.dst_port);
    /* TCP */
    if (sample->s.dcd_ipProtocol == 6) {
        sample->s.dcd_tcpFlags = ntohl(nfKey6.tcp_flags);
    }
}

static void readFlowSample_header(SFSample *sample)
{
    sample->s.headerProtocol = getData32(sample);
    sample->s.sampledPacketSize = getData32(sample);
    if (sample->datagramVersion > 4) {
        /* stripped count introduced in sFlow version 5 */
        sample->s.stripped = getData32(sample);
    }
    sample->s.headerLen = getData32(sample);
    sample->s.header = (uint8_t *)sample->datap; /* just point at the header */
    skipBytes(sample, sample->s.headerLen);

    switch (sample->s.headerProtocol) {
        /* the header protocol tells us where to jump into the decode */
    case SFLHEADER_ETHERNET_ISO8023:
        decodeLinkLayer(sample);
        break;
    case SFLHEADER_IPv4:
        sample->s.gotIPV4 = 1;
        sample->s.offsetToIPV4 = 0;
        break;
    case SFLHEADER_IPv6:
        sample->s.gotIPV6 = 1;
        sample->s.offsetToIPV6 = 0;
        break;
    case SFLHEADER_IEEE80211MAC:
        decode80211MAC(sample);
        break;
    case SFLHEADER_ISO88024_TOKENBUS:
    case SFLHEADER_ISO88025_TOKENRING:
    case SFLHEADER_FDDI:
    case SFLHEADER_FRAME_RELAY:
    case SFLHEADER_X25:
    case SFLHEADER_PPP:
    case SFLHEADER_SMDS:
    case SFLHEADER_AAL5:
    case SFLHEADER_AAL5_IP:
    case SFLHEADER_MPLS:
    case SFLHEADER_POS:
    case SFLHEADER_IEEE80211_AMPDU:
    case SFLHEADER_IEEE80211_AMSDU_SUBFRAME:
        break;
    default:
        throw std::invalid_argument(fmt::format("undefined headerProtocol = {}", sample->s.headerProtocol));
    }

    if (sample->s.gotIPV4) {
        decodeIPV4(sample);
    } else if (sample->s.gotIPV6) {
        decodeIPV6(sample);
    }
}

static void readFlowSample_v2v4(SFSample *sample)
{
    sample->s.samplesGenerated = getData32(sample);

    uint32_t samplerId = getData32(sample);
    sample->s.ds_class = samplerId >> 24;
    sample->s.ds_index = samplerId & 0x00ffffff;

    sample->s.meanSkipCount = getData32(sample);
    sample->s.samplePool = getData32(sample);
    sample->s.dropEvents = getData32(sample);
    sample->s.inputPort = getData32(sample);
    sample->s.outputPort = getData32(sample);

    sample->s.packet_data_tag = getData32(sample);

    switch (sample->s.packet_data_tag) {

    case INMPACKETTYPE_HEADER:
        readFlowSample_header(sample);
        break;
    case INMPACKETTYPE_IPV4:
        sample->s.gotIPV4Struct = 1;
        readFlowSample_IPv4(sample);
        break;
    case INMPACKETTYPE_IPV6:
        sample->s.gotIPV6Struct = 1;
        readFlowSample_IPv6(sample);
        break;
    default:
        throw std::invalid_argument("unexpected packet_data_tag");
        break;
    }

    sample->s.extended_data_tag = 0;

    sample->s.num_extended = getData32(sample);
    if (sample->s.num_extended > 0) {
        throw std::invalid_argument("do not support extended data tag");
    }
}

static void readFlowSample(SFSample *sample, bool expanded)
{
    uint32_t num_elements, sampleLength;
    uint8_t *sampleStart;

    sampleLength = getData32(sample);
    sampleStart = (uint8_t *)sample->datap;
    sample->s.samplesGenerated = getData32(sample);
    if (expanded) {
        sample->s.ds_class = getData32(sample);
        sample->s.ds_index = getData32(sample);
    } else {
        uint32_t samplerId = getData32(sample);
        sample->s.ds_class = samplerId >> 24;
        sample->s.ds_index = samplerId & 0x00ffffff;
    }

    sample->s.meanSkipCount = getData32(sample);
    sample->s.samplePool = getData32(sample);
    sample->s.dropEvents = getData32(sample);
    if (expanded) {
        sample->s.inputPortFormat = getData32(sample);
        sample->s.inputPort = getData32(sample);
        sample->s.outputPortFormat = getData32(sample);
        sample->s.outputPort = getData32(sample);
    } else {
        uint32_t inp, outp;
        inp = getData32(sample);
        outp = getData32(sample);
        sample->s.inputPortFormat = inp >> 30;
        sample->s.outputPortFormat = outp >> 30;
        sample->s.inputPort = inp & 0x3fffffff;
        sample->s.outputPort = outp & 0x3fffffff;
    }

    num_elements = getData32(sample);

    uint32_t el;
    for (el = 0; el < num_elements; el++) {
        uint32_t tag, length;
        uint8_t *start;
        tag = sample->s.elementType = getData32(sample);
        length = getData32(sample);
        start = (uint8_t *)sample->datap;

        if (tag == SFLFLOW_HEADER) {
            readFlowSample_header(sample);
        } else {
            skipBytes(sample, getData32(sample));
        }
        lengthCheck(sample, "flow_sample_element", start, length);
    }
    lengthCheck(sample, "flow_sample", sampleStart, sampleLength);
}

static void read_sflow_datagram(SFSample *sample)
{
    sample->datap = reinterpret_cast<uint32_t *>(sample->rawSample);
    sample->endp = reinterpret_cast<uint8_t *>(sample->rawSample + sample->rawSampleLen);

    sample->datagramVersion = getData32(sample);

    if (sample->datagramVersion != 2 && sample->datagramVersion != 4 && sample->datagramVersion != 5) {
        throw std::invalid_argument("only support sflow v2, v4 and v5");
    }

    /* get the agent address */
    getAddress(sample, &sample->agent_addr);

    /* version 5 has an agent sub-id as well */
    if (sample->datagramVersion >= 5) {
        sample->agentSubId = getData32(sample);
    }

    sample->sequenceNo = getData32(sample); /* this is the packet sequence number */
    sample->sysUpTime = getData32(sample);
    uint32_t samplesInPacket = getData32(sample);

    uint32_t samp = 0;
    for (; samp < samplesInPacket; samp++) {
        if (reinterpret_cast<uint8_t *>(sample->datap) >= sample->endp) {
            throw std::out_of_range(fmt::format("unexpected end of datagram after sample {} of {}", samp, samplesInPacket));
        }
        // clear all per-sample fields
        std::memset(&sample->s, 0, sizeof(sample->s));
        /* just read the tag, then call the approriate decode fn */
        sample->s.elementType = 0;
        sample->s.sampleType = getData32(sample);

        if (sample->datagramVersion >= 5) {
            switch (sample->s.sampleType) {
            case SFLFLOW_SAMPLE:
                readFlowSample(sample, false);
                break;
            case SFLCOUNTERS_SAMPLE:
                // counter is performed in handlers
                skipBytes(sample, getData32(sample));
                break;
            case SFLFLOW_SAMPLE_EXPANDED:
                readFlowSample(sample, true);
                break;
            case SFLCOUNTERS_SAMPLE_EXPANDED:
                // counter is performed in handlers
                skipBytes(sample, getData32(sample));
                break;
            case SFLEVENT_DISCARDED_PACKET:
                // readDiscardSample(sample);
                // break;
            case SFLRTMETRIC:
                // readRTMetric(sample);
                // break;
            case SFLRTFLOW:
                // readRTFlow(sample);
                // break;
            default:
                skipBytes(sample, getData32(sample));
                break;
            }
        } else {
            switch (sample->s.sampleType) {
            case FLOWSAMPLE:
                readFlowSample_v2v4(sample);
                break;
            case COUNTERSSAMPLE:
                // counter is performed in handlers
                skipBytes(sample, getData32(sample));
                break;
            default:
                throw std::invalid_argument("unexpected sample type");
            }
        }
    }
}

}
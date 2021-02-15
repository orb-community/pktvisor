#include "afpacket.h"

#include "utils.h"
#include <Packet.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fmt/format.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

namespace vizer::input::pcap {

AFPacket::AFPacket(PcapInputStream *stream, pcpp::OnPacketArrivesCallback cb, std::string filter,
    std::string interface_name,
    int fanout_group_id,
    unsigned int block_size,
    unsigned int frame_size,
    unsigned int num_blocks)
    : fd(-1)
    , inputStream(stream)
    , block_size(block_size)
    , frame_size(frame_size)
    , num_blocks(num_blocks)
    , interface(-1)
    , interface_type(-1)
    , interface_name(std::move(interface_name))
    , bpf()
    , filter(std::move(filter))
    , fanout_group_id(fanout_group_id)
    , map(nullptr)
    , cb(std::move(cb))
{
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (fd == -1) {
        throw PcapException(fmt::format(
            "Failed to create AF_PACKET socket: {}\n", strerror(errno)));
    }
}

AFPacket::~AFPacket()
{
    if (fd != -1) {
        close(fd);
        fd = -1;
    }
    if (map != nullptr) {
        munmap(map, block_size * num_blocks);
    }
}

void AFPacket::flush_block(struct block_desc *pbd)
{
    pbd->h1.block_status = TP_STATUS_KERNEL;
}

void AFPacket::walk_block(struct block_desc *pbd)
{
    int num_pkts = pbd->h1.num_pkts, i;
    uint64_t bytes = 0;
    struct tpacket3_hdr *ppd;
    struct sockaddr_ll *sll;

    ppd = (struct tpacket3_hdr *)((uint8_t *)pbd + pbd->h1.offset_to_first_pkt);
    for (i = 0; i < num_pkts; ++i) {
        bytes += ppd->tp_snaplen;

        u_int8_t timestamp = 0;
        u_int8_t add_hash = 0;

        auto data_pointer = (uint8_t *)ppd + ppd->tp_mac;
        pcpp::RawPacket packet(data_pointer, ppd->tp_snaplen, timespec{pbd->h1.ts_last_pkt.ts_sec, pbd->h1.ts_last_pkt.ts_nsec},
            false, pcpp::LINKTYPE_ETHERNET);
        cb(&packet, nullptr, inputStream);

        ppd = (struct tpacket3_hdr *)((uint8_t *)ppd + ppd->tp_next_offset);
    }
}

void AFPacket::set_interface()
{
    if (interface_name == "any") {
        interface = 0;
        interface_type = 0;
        return;
    }

    struct ifreq ifr {
    };
    memset(&ifr, 0, sizeof(ifr));

    if (interface_name.size() > IFNAMSIZ) {
        throw PcapException(fmt::format("Invalid argument: interface name is to long got '{}'", interface_name));
    }

    strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        throw PcapException(fmt::format("Failed to get interface index from name '{}': {}", interface_name, strerror(errno)));
    }
    interface = ifr.ifr_ifindex;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        throw PcapException(fmt::format("Failed to get interface type from name '{}': {}", interface_name, strerror(errno)));
    }
    interface_type = ifr.ifr_hwaddr.sa_family;
}

void AFPacket::set_socket_opts()
{
    // Set the packet version to TPACKET_V3
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &VERSION, sizeof(VERSION)) == -1) {
        throw PcapException(
            fmt::format("Failed to set packet v3 version on AF_PACKET socket: {}\n",
                strerror(errno)));
    }

    // Enable promisc mode for the socket if not listening on 'any'.
    if (interface > 0) {
        struct packet_mreq sock_params {
        };
        memset(&sock_params, 0, sizeof(sock_params));
        sock_params.mr_type = PACKET_MR_PROMISC;
        sock_params.mr_ifindex = interface;

        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&sock_params,
                sizeof(sock_params))
            == -1) {
            throw PcapException(
                fmt::format("Failed to enable promisc mode on AF_PACKET socket: {}\n",
                    strerror(errno)));
        }
    }

    if (!filter.empty()) {
        memset(&bpf, 0, sizeof(bpf));
        filter_try_compile(filter, &bpf, interface_type);

        if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) == -1) {
            throw PcapException(
                fmt::format("Failed to attach supplied BPF filter to AF_PACKET socket: {}\n",
                    strerror(errno)));
        }

        int lock = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &lock, sizeof(lock)) == -1) {
            throw PcapException(
                fmt::format("Failed to lock supplied BPF filter to AF_PACKET socket: {}\n",
                    strerror(errno)));
        }
    }

    // Enable PACKET_RX_RING for the socket
    struct tpacket_req3 req {
    };
    memset(&req, 0, sizeof(req));

    req.tp_block_size = block_size;
    req.tp_frame_size = frame_size;
    req.tp_block_nr = num_blocks;
    req.tp_frame_nr = (block_size * num_blocks) / frame_size;

    req.tp_retire_blk_tov = 60; // Timeout in msec
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req)) == -1) {
        throw PcapException(
            fmt::format("Failed to enable RX_RING for AF_PACKET socket: {}\n",
                strerror(errno)));
    }
}

void AFPacket::setup()
{
    set_interface();
    set_socket_opts();

    // Enable mmap for PACKET_RX_RING.
    map = (uint8_t *)mmap(nullptr, block_size * num_blocks, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_LOCKED, fd, 0);

    if (map == MAP_FAILED) {
        throw PcapException(fmt::format(
            "Failed to initialize RX_RING mmap: {}\n", strerror(errno)));
    }

    // Allocate iov structure for each block
    rd.reserve(num_blocks); // = (struct iovec *)malloc(num_blocks * sizeof(struct iovec));

    // Initilize iov structures
    for (int i = 0; i < num_blocks; ++i) {
        struct iovec cur {
        };
        cur.iov_base = map + (i * block_size);
        cur.iov_len = block_size;
        rd.push_back(cur);
    }

    // Bind the fully configured socket. If necessary.
    struct sockaddr_ll bind_address {
    };
    memset(&bind_address, 0, sizeof(bind_address));

    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = interface;
    bind_address.sll_hatype = 0;
    bind_address.sll_pkttype = 0;
    bind_address.sll_halen = 0;

    if (bind(fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) == -1) {
        throw PcapException(fmt::format(
            "Failed binding the AF_PACKET socket {} to the specified interface '{}' ({}): {}\n",
            fd, interface_name, interface, strerror(errno)));
    }

    // Setup fanout if enabled.
    if (fanout_group_id != -1) {
        // PACKET_FANOUT_LB - round robin
        // PACKET_FANOUT_CPU - send packets to CPU where packet arrived
        int fanout_type = PACKET_FANOUT_LB;

        int fanout_arg = (fanout_group_id | (fanout_type << 16));

        if (setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg,
                sizeof(fanout_arg))
            < 0) {
            throw PcapException(
                fmt::format("Failed to configure fanout for AF_PACKET socket: {}\n",
                    strerror(errno)));
        }
    }
}

void AFPacket::start_capture()
{
    // Configure the packet socket.
    setup();

    // Setup poller to watch for new packets.
    unsigned int current_block_num = 0;

    struct pollfd pfd {
    };
    memset(&pfd, 0, sizeof(pfd));

    pfd.fd = fd;
    pfd.events = POLLIN | POLLERR;
    pfd.revents = 0;

    while (true) {
        auto pbd = (struct block_desc *)rd[current_block_num].iov_base;

        if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
            poll(&pfd, 1, -1);

            continue;
        }

        walk_block(pbd);
        flush_block(pbd);
        current_block_num = (current_block_num + 1) % num_blocks;
    }
}

void filter_try_compile(const std::string &filter, struct sock_fprog *bpf, int link_type)
{
    int i, ret;
    const struct bpf_insn *ins;
    struct sock_filter *out;
    struct bpf_program prog {
    };

    // Assume ether if we are listening on 'any'
    if (link_type == 0) {
        link_type = 1;
    }

    ret = pcap_compile_nopcap(65535, link_type, &prog, filter.c_str(), 1, 0xffffffff);
    if (ret < 0) {
        throw PcapException(fmt::format("Failed to parse bpf filter '{}'", filter));
    }

    bpf->len = prog.bf_len;
    bpf->filter = (struct sock_filter *)malloc(bpf->len * sizeof(struct sock_filter));
    if (bpf->filter == nullptr) {
        throw PcapException("Failed to generating bpf filter: Out of memory");
    }

    for (i = 0, ins = prog.bf_insns, out = bpf->filter; i < bpf->len;
         ++i, ++ins, ++out) {
        out->code = ins->code;
        out->jt = ins->jt;
        out->jf = ins->jf;
        out->k = ins->k;

        if (out->code == 0x06 && out->k > 0) {
            out->k = 0xFFFFFFFF;
        }
    }

    pcap_freecode(&prog);
}

}

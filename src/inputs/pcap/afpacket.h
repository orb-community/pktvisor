/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <PcapLiveDevice.h>
#pragma GCC diagnostic pop
#include <atomic>
#include <cstdint>
#include <functional>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <string>
#include <sys/uio.h>
#include <thread>

namespace vizer::input::pcap {

const int physical_offset = TPACKET_ALIGN(sizeof(struct tpacket3_hdr));

static const int VERSION = TPACKET_V3;

struct block_desc {
    uint32_t version;
    uint32_t offset_to_priv;
    struct tpacket_hdr_v1 h1;
};

class PcapInputStream;

class AFPacket final
{
    int fd;

    unsigned int block_size;
    unsigned int frame_size;
    unsigned int num_blocks;

    int interface;
    int interface_type;
    std::string interface_name;

    struct sock_fprog bpf;
    std::string filter;

    int fanout_group_id;

    std::vector<struct iovec> rd;
    uint8_t *map;

    pcpp::OnPacketArrivesCallback cb;
    PcapInputStream *inputStream;

    void flush_block(struct block_desc *pbd);
    void walk_block(struct block_desc *pbd);

    void set_interface();
    void set_socket_opts();
    void setup();

    std::atomic<bool> running;
    std::unique_ptr<std::thread> cap_thread;

public:
    AFPacket(PcapInputStream *stream, pcpp::OnPacketArrivesCallback cb, std::string filter,
        std::string interface_name,
        int fanout_group_id = -1,
        unsigned int block_size = 1 << 22,
        unsigned int frame_size = 1 << 11,
        unsigned int num_blocks = 64);
    ~AFPacket();

    void start_capture();
    void stop_capture()
    {
        running = false;
    }
};

void filter_try_compile(const std::string &, struct sock_fprog *, int);

} // namespace vizer

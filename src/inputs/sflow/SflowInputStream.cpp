/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "SflowInputStream.h"
#include "SflowException.h"
#include <Packet.h>
#include <PcapFileDevice.h>
#include <UdpLayer.h>
namespace visor::input::sflow {

SflowInputStream::SflowInputStream(const std::string &name)
    : visor::InputStream(name)
    , _error_count(0)
{
    _logger = spdlog::get("visor");
    assert(_logger);
}

void SflowInputStream::start()
{

    if (_running) {
        return;
    }

    if (config_exists("pcap_file")) {
        // read sflow from pcap file. this is a special case from a command line utility
        _running = true;
        _read_from_pcap_file();
        return;
    } else if (config_exists("port") && config_exists("bind")) {
        _create_frame_stream_udp_socket();
    } else {
        throw SflowException("sflow config must specify port and bind");
    }

    _running = true;
}

void SflowInputStream::_read_from_pcap_file()
{
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(config_get<std::string>("pcap_file"));
    reader->open();

    pcpp::RawPacket rawPacket;

    datasketches::frequent_items_sketch<uint16_t> sketch(3);

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet sflow_pkt(&rawPacket);
        if (sflow_pkt.isPacketOfType(pcpp::UDP)) {
            pcpp::UdpLayer *udpLayer = sflow_pkt.getLayerOfType<pcpp::UdpLayer>();
            SFSample sample;
            std::memset(&sample, 0, sizeof(sample));
            sample.rawSample = udpLayer->getLayerPayload();
            sample.rawSampleLen = udpLayer->getLayerPayloadSize();
            try {
                read_sflow_datagram(&sample);
                sflow_signal(sample);
                cache_sflow_signal.clear();
            } catch (const std::exception &e) {
                _logger->error(e.what());
            }
        }
    }

    reader->close();
    delete reader;
}

void SflowInputStream::_create_frame_stream_udp_socket()
{
    auto bind = config_get<std::string>("bind");
    auto port = config_get<uint64_t>("port");
    // main io loop, run in its own thread
    _io_loop = uvw::Loop::create();
    if (!_io_loop) {
        throw SflowException("unable to create io loop");
    }
    // AsyncHandle lets us stop the loop from its own thread
    _async_h = _io_loop->resource<uvw::AsyncHandle>();
    if (!_async_h) {
        throw SflowException("unable to initialize AsyncHandle");
    }
    _async_h->once<uvw::AsyncEvent>([this](const auto &, auto &handle) {
        _udp_server_h->stop();
        _udp_server_h->close();
        _io_loop->stop();
        _io_loop->close();
        handle.close();
    });
    _async_h->on<uvw::ErrorEvent>([this](const auto &err, auto &handle) {
        _logger->error("[{}] AsyncEvent error: {}", _name, err.what());
        handle.close();
    });

    // setup server socket
    _udp_server_h = _io_loop->resource<uvw::UDPHandle>();
    if (!_udp_server_h) {
        throw SflowException("unable to initialize server PipeHandle");
    }

    _udp_server_h->on<uvw::ErrorEvent>([this](const auto &err, auto &) {
        _logger->error("[{}] socket error: {}", _name, err.what());
        throw SflowException(err.what());
    });

    // ListenEvent happens on client connection
    _udp_server_h->on<uvw::UDPDataEvent>([this](const uvw::UDPDataEvent &event, uvw::UDPHandle &) {
        SFSample sample;
        std::memset(&sample, 0, sizeof(sample));
        sample.rawSample = reinterpret_cast<uint8_t *>(event.data.get());
        sample.rawSampleLen = event.length;
        sample.sourceIP.type = SFLADDRESSTYPE_IP_V4;
        struct sockaddr_in peer4;
        inet_pton(AF_INET, event.sender.ip.c_str(), &(peer4.sin_addr));
        std::memcpy(&sample.sourceIP.address.ip_v4.addr, &peer4.sin_addr, 4);
        try {
            read_sflow_datagram(&sample);
            sflow_signal(sample);
            cache_sflow_signal.clear();
        } catch (const std::exception &e) {
            ++_error_count;
        }
    });

    _logger->info("[{}] binding sflow UDP server on {}:{}", _name, bind, port);
    _udp_server_h->bind(bind, port);
    _udp_server_h->recv();

    // spawn the loop
    _io_thread = std::make_unique<std::thread>([this] {
        _io_loop->run();
    });
}

void SflowInputStream::stop()
{
    if (!_running) {
        return;
    }

    if (_async_h && _io_thread) {
        // we have to use AsyncHandle to stop the loop from the same thread the loop is running in
        _async_h->send();
        // waits for _io_loop->run() to return
        if (_io_thread->joinable()) {
            _io_thread->join();
        }
    }

    _running = false;
}

void SflowInputStream::info_json(json &j) const
{
    common_info_json(j);
    j[schema_key()]["packet_errors"] = _error_count.load();
}

}
